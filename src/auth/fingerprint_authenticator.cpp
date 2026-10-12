#include "auth/fingerprint_authenticator.h"

#include "core/log.h"
#include "dbus/system_bus.h"
#include "i18n/i18n.h"

#include <chrono>
#include <map>
#include <optional>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>
#include <string>
#include <utility>

namespace {
  constexpr Logger kLog("fingerprint");

  const sdbus::ServiceName kFprintBusName{"net.reactivated.Fprint"};
  const sdbus::ObjectPath kManagerPath{"/net/reactivated/Fprint/Manager"};
  constexpr auto kManagerInterface = "net.reactivated.Fprint.Manager";
  constexpr auto kDeviceInterface = "net.reactivated.Fprint.Device";
  constexpr auto kPropertiesInterface = "org.freedesktop.DBus.Properties";

  const sdbus::ServiceName kLoginBusName{"org.freedesktop.login1"};
  const sdbus::ObjectPath kLoginPath{"/org/freedesktop/login1"};
  constexpr auto kLoginManagerInterface = "org.freedesktop.login1.Manager";

  constexpr int kMaxRetries = 3;
  constexpr auto kRetryDelay = std::chrono::milliseconds(250);
  // Bounds every fprintd round-trip. Async calls never block the UI thread, but without a timeout
  // a wedged fprintd (e.g. Goodix 0xc6 protocol storm after resume) leaves the call pending and the
  // authenticator stuck in claiming/verifying limbo.
  constexpr auto kCallTimeout = std::chrono::seconds(3);
  // Chained-failure cap before fingerprint disarms itself for the session (with backoff between
  // restarts). A sick device must degrade to password, never churn or freeze the lockscreen.
  constexpr int kMaxChainedFailures = 5;
  constexpr auto kMaxRestartBackoff = std::chrono::milliseconds(4000);
  // Wake settle: outputs, fprintd re-init and the first lock frame all land in the first seconds
  // after resume. An immediate VerifyStart races fprintd's post-restart driver init on Goodix
  // hardware and can wedge it into a protocol-error storm, burning the exact window the lock
  // screen needs to repaint. Defer the wake re-arm briefly; explicit user action still verifies
  // via the normal start() path.
  constexpr auto kWakeSettleDelay = std::chrono::seconds(4);

  enum class MatchResult {
    Invalid,
    NoMatch,
    Matched,
    Retry,
    SwipeTooShort,
    FingerNotCentered,
    RemoveAndRetry,
    Disconnected,
    UnknownError,
  };

  MatchResult parseVerifyResult(const std::string& result) {
    static const std::map<std::string, MatchResult> kResults = {
        {"verify-no-match", MatchResult::NoMatch},
        {"verify-match", MatchResult::Matched},
        {"verify-retry-scan", MatchResult::Retry},
        {"verify-swipe-too-short", MatchResult::SwipeTooShort},
        {"verify-finger-not-centered", MatchResult::FingerNotCentered},
        {"verify-remove-and-retry", MatchResult::RemoveAndRetry},
        {"verify-disconnected", MatchResult::Disconnected},
        {"verify-unknown-error", MatchResult::UnknownError},
    };
    const auto it = kResults.find(result);
    return it == kResults.end() ? MatchResult::Invalid : it->second;
  }

  bool isRecoverableVerifyStartError(const sdbus::Error& error) {
    // Suspend/resume can drop the claim while the proxy survives; only that case is worth
    // recreating+reclaiming. Other VerifyStart failures are permanent for this lock attempt.
    return error.getName() == sdbus::Error::Name{"net.reactivated.Fprint.Error.ClaimDevice"};
  }
} // namespace

FingerprintAuthenticator::FingerprintAuthenticator(SystemBus& bus) : m_bus(bus) {
  try {
    // Name-based proxy: survives fprintd restarts across suspend/resume without recreation.
    m_manager = sdbus::createProxy(m_bus.connection(), kFprintBusName, kManagerPath);
    m_loginManager = sdbus::createProxy(m_bus.connection(), kLoginBusName, kLoginPath);
    // on sleep, leave the device to fprintd; on resume, re-arm if still active. The re-arm goes
    // through startVerify(), whose async health probe (GetDefaultDevice with timeout) refuses a
    // sick device instead of verifying into a storm, so no separate wake path is needed.
    m_loginManager->uponSignal("PrepareForSleep").onInterface(kLoginManagerInterface).call([this](bool sleeping) {
      m_sleeping = sleeping;
      if (sleeping) {
        // Do not call into fprintd here. It handles PrepareForSleep itself and has
        // already powered the sensor down; a call arriving after that never gets a
        // reply and blocks until logind freezes the session mid-transfer, leaving
        // the sensor with a stalled endpoint on resume. startVerify() already
        // refuses to run while m_sleeping, so only the re-arm state needs clearing.
        m_retryTimer.stop();
        m_wakeSettleTimer.stop();
        m_verifying = false;
      } else if (m_active && !m_abort) {
        m_wakeSettleTimer.start(kWakeSettleDelay, [this, generation = m_generation]() {
          if (generation == m_generation && m_active && !m_sleeping && !m_abort) {
            startVerify(false);
          }
        });
      }
    });
  } catch (const sdbus::Error& e) {
    kLog.debug("could not monitor PrepareForSleep: {}", e.what());
    m_loginManager.reset();
  }
}

FingerprintAuthenticator::~FingerprintAuthenticator() { stop(); }

void FingerprintAuthenticator::setAuthenticatedCallback(AuthenticatedCallback callback) {
  m_onAuthenticated = std::move(callback);
}

void FingerprintAuthenticator::setStatusCallback(StatusCallback callback) { m_onStatus = std::move(callback); }

void FingerprintAuthenticator::start() {
  if (m_active) {
    return;
  }

  m_active = true;
  m_abort = false;
  m_unavailable = false;
  m_retries = 0;
  m_consecutiveFailures = 0;
  m_reclaimAttempted = false;
  m_generation++;
  if (m_sleeping) {
    return;
  }
  startVerify(false);
}

void FingerprintAuthenticator::stop() {
  m_retryTimer.stop();
  m_wakeSettleTimer.stop();
  m_active = false;
  m_verifying = false;
  m_claiming = false;
  m_generation++;
  // Release even after verify-disconnected: fprintd also reports libfprint's recoverable TOO_HOT
  // cutoff that way and keeps our claim until Release or until this long-lived connection closes.
  releaseDevice();
}

void FingerprintAuthenticator::ensureDeviceProxyAsync(DeviceReadyCallback done) {
  if (m_device != nullptr) {
    done(true);
    return;
  }
  if (m_manager == nullptr) {
    done(false);
    return;
  }
  // Async with timeout doubles as the wake health probe: a wedged fprintd answers with an error
  // or not at all (timeout), and the caller degrades to password instead of blocking the UI.
  const int generation = m_generation;
  try {
    m_manager->callMethodAsync("GetDefaultDevice")
        .onInterface(kManagerInterface)
        .withTimeout(kCallTimeout)
        .uponReplyInvoke([this, generation, done](std::optional<sdbus::Error> error, sdbus::ObjectPath path) {
          if (generation != m_generation) {
            return; // stopped or restarted while the probe was in flight
          }
          if (error.has_value()) {
            kLog.info("no fprintd device available: {}", error->what());
            done(false);
            return;
          }
          kLog.info("using fingerprint device {}", path.c_str());
          try {
            m_device = sdbus::createProxy(m_bus.connection(), kFprintBusName, path);
          } catch (const sdbus::Error& e) {
            kLog.warn("could not create device proxy: {}", e.what());
            m_device.reset();
            done(false);
            return;
          }
          attachDeviceSignals();
          done(true);
        });
  } catch (const sdbus::Error& e) {
    kLog.info("no fprintd device available: {}", e.what());
    done(false);
  }
}

void FingerprintAuthenticator::attachDeviceSignals() {
  m_device->uponSignal("VerifyStatus").onInterface(kDeviceInterface).call([this](const std::string& result, bool done) {
    handleVerifyStatus(result, done);
  });

  m_device->uponSignal("PropertiesChanged")
      .onInterface(kPropertiesInterface)
      .call([this](
                const std::string& interfaceName, const std::map<std::string, sdbus::Variant>& changed,
                const std::vector<std::string>& /*invalidated*/
            ) {
        if (interfaceName != kDeviceInterface) {
          return;
        }
        const auto it = changed.find("finger-present");
        if (it == changed.end()) {
          return;
        }
        try {
          if (it->second.get<bool>()) {
            emitStatus(i18n::tr("auth.fingerprint.present"), false);
          }
        } catch (const sdbus::Error&) {
        }
      });
}

void FingerprintAuthenticator::claimDevice() {
  if (m_device == nullptr || m_claiming) {
    return;
  }
  m_claiming = true;

  // Timeout bounds the wait: without it a lost reply leaves m_claiming set forever and every
  // later startVerify() early-returns on it, silently wedging fingerprint for the session.
  const int generation = m_generation;
  try {
    m_device->callMethodAsync("Claim")
        .onInterface(kDeviceInterface)
        .withArguments(std::string{})
        .withTimeout(kCallTimeout)
        .uponReplyInvoke([this, generation](std::optional<sdbus::Error> e) {
          m_claiming = false;
          if (generation != m_generation) {
            return;
          }
          if (e.has_value()) {
            kLog.info("could not claim fingerprint device: {}", e->what());
            m_verifying = false;
            noteFailure();
            return;
          }
          kLog.info("claimed fingerprint device");
          noteSuccess();
          if (m_active && !m_sleeping && !m_unavailable) {
            startVerify(false);
          }
        });
  } catch (const sdbus::Error& e) {
    m_claiming = false;
    kLog.info("could not claim fingerprint device: {}", e.what());
    m_verifying = false;
    noteFailure();
  }
}

void FingerprintAuthenticator::startVerify(bool isRetry) {
  if (!m_active || m_sleeping || m_abort || m_unavailable) {
    return;
  }
  m_verifying = true;

  if (m_device == nullptr) {
    ensureDeviceProxyAsync([this, generation = m_generation](bool ready) {
      if (generation != m_generation) {
        return;
      }
      if (!ready) {
        m_verifying = false;
        noteFailure();
        return;
      }
      emitStatus(i18n::tr("auth.fingerprint.ready"), false);
      claimDevice();
    });
    return;
  }
  if (m_claiming) {
    return;
  }

  const int generation = m_generation;
  m_device->callMethodAsync("VerifyStart")
      .onInterface(kDeviceInterface)
      .withArguments(std::string{"any"})
      .withTimeout(kCallTimeout)
      .uponReplyInvoke([this, isRetry, generation](std::optional<sdbus::Error> e) {
        if (generation != m_generation) {
          return;
        }
        if (e.has_value()) {
          kLog.info("could not start fingerprint verification: {}", e->what());
          m_verifying = false;
          noteFailure();
          // A claim dropped across suspend/resume makes VerifyStart fail with ClaimDevice; drop the
          // stale proxy and recreate+reclaim once. Destroying the proxy here would use-after-free
          // the async reply handler, so defer the reset until after it returns.
          if (!m_reclaimAttempted
              && !m_unavailable
              && m_active
              && !m_sleeping
              && !m_abort
              && isRecoverableVerifyStartError(*e)) {
            m_reclaimAttempted = true;
            m_retryTimer.start(kRetryDelay, [this]() {
              m_device.reset();
              startVerify(false);
            });
            return;
          }
          if (!m_unavailable) {
            emitStatus({}, false); // issue loading: drop the status message
          }
          return;
        }
        kLog.debug("fingerprint verification started");
        m_reclaimAttempted = false;
        noteSuccess();
        if (isRetry) {
          m_retries++;
        }
        emitStatus(i18n::tr("auth.fingerprint.ready"), false);
      });
}

void FingerprintAuthenticator::stopVerify() {
  m_retryTimer.stop();
  m_verifying = false;
  if (m_device == nullptr) {
    return;
  }
  // Fire-and-forget async: the old sync call blocked the whole lockscreen UI whenever fprintd was
  // wedged (Goodix post-resume storm), which is exactly the reported freeze. The handler only logs.
  try {
    m_device->callMethodAsync("VerifyStop")
        .onInterface(kDeviceInterface)
        .withTimeout(kCallTimeout)
        .uponReplyInvoke([](std::optional<sdbus::Error> e) {
          if (e.has_value()) {
            kLog.debug("could not stop fingerprint verification: {}", e->what());
          } else {
            kLog.debug("fingerprint verification stopped");
          }
        });
  } catch (const sdbus::Error& e) {
    kLog.debug("could not stop fingerprint verification: {}", e.what());
  }
}

void FingerprintAuthenticator::releaseDevice() {
  if (m_device == nullptr) {
    return;
  }
  // Same fire-and-forget reasoning as stopVerify(): never block the UI on a sick fprintd.
  // Issued and reset back-to-back on the main loop, so no reply can interleave; a late reply
  // after proxy teardown is dropped by sdbus, and the handler only logs anyway.
  try {
    m_device->callMethodAsync("Release")
        .onInterface(kDeviceInterface)
        .withTimeout(kCallTimeout)
        .uponReplyInvoke([](std::optional<sdbus::Error> e) {
          if (e.has_value()) {
            kLog.debug("could not release fingerprint device: {}", e->what());
          } else {
            kLog.info("released fingerprint device");
          }
        });
  } catch (const sdbus::Error& e) {
    kLog.debug("could not release fingerprint device: {}", e.what());
  }
  m_device.reset();
}

void FingerprintAuthenticator::noteFailure() {
  if (m_unavailable) {
    return;
  }
  if (++m_consecutiveFailures >= kMaxChainedFailures) {
    m_unavailable = true;
    stopVerify();
    emitStatus(i18n::tr("auth.fingerprint.unavailable"), true);
    kLog.warn("disabling fingerprint for this session after {} consecutive failures", m_consecutiveFailures);
  }
}

void FingerprintAuthenticator::noteSuccess() { m_consecutiveFailures = 0; }

std::chrono::milliseconds FingerprintAuthenticator::restartBackoff() const {
  const int shift = std::min(m_consecutiveFailures, 4);
  return std::min(kRetryDelay * (1 << shift), kMaxRestartBackoff);
}

void FingerprintAuthenticator::handleVerifyStatus(const std::string& result, bool done) {
  if (!m_active) {
    return;
  }
  if (m_sleeping) {
    stopVerify();
    return;
  }

  kLog.debug("verify status: {} (done={})", result, done);
  const MatchResult match = parseVerifyResult(result);

  bool authenticated = false;
  bool retryInPlace = false;
  // Set when a branch fully owns the post-verify restart decision (capped rearm or deliberate stop),
  // so the generic done-restart below does not also fire.
  bool ownsRestart = false;

  switch (match) {
  case MatchResult::Invalid:
    kLog.warn("unknown fingerprint verify status: {}", result);
    break;
  case MatchResult::Matched:
    stopVerify();
    authenticated = true;
    break;
  case MatchResult::NoMatch:
    stopVerify();
    ownsRestart = true;
    if (m_retries >= kMaxRetries) {
      emitStatus(i18n::tr("auth.fingerprint.too-many-attempts"), true);
    } else {
      emitStatus(i18n::tr("auth.fingerprint.no-match"), true);
      // rearm after a short delay
      m_retryTimer.start(kRetryDelay, [this]() { startVerify(true); });
    }
    break;
  case MatchResult::Retry:
    retryInPlace = true;
    emitStatus(i18n::tr("auth.fingerprint.retry"), false);
    break;
  case MatchResult::SwipeTooShort:
    retryInPlace = true;
    emitStatus(i18n::tr("auth.fingerprint.swipe-too-short"), false);
    break;
  case MatchResult::FingerNotCentered:
    retryInPlace = true;
    emitStatus(i18n::tr("auth.fingerprint.not-centered"), false);
    break;
  case MatchResult::RemoveAndRetry:
    retryInPlace = true;
    emitStatus(i18n::tr("auth.fingerprint.remove-and-retry"), false);
    break;
  case MatchResult::Disconnected:
    stopVerify();
    m_abort = true;
    emitStatus(i18n::tr("auth.fingerprint.disconnected"), true);
    break;
  case MatchResult::UnknownError:
    stopVerify();
    ownsRestart = true;
    if (m_retries >= kMaxRetries) {
      emitStatus(i18n::tr("auth.fingerprint.too-many-attempts"), true);
    } else {
      emitStatus(i18n::tr("auth.fingerprint.error"), true);
      m_retryTimer.start(kRetryDelay, [this]() { startVerify(true); });
    }
    break;
  }

  if (authenticated) {
    if (m_onAuthenticated) {
      m_onAuthenticated();
    }
    return;
  }

  // In-place retries keep verifying; otherwise restart only when fprintd reports done, with
  // backoff and a chained-failure cap so a misbehaving device degrades to password instead of
  // churning VerifyStart forever.
  if (!retryInPlace && !ownsRestart && done && !m_abort && !m_unavailable && m_active && !m_sleeping) {
    noteFailure();
    if (!m_unavailable) {
      m_retryTimer.start(restartBackoff(), [this]() { startVerify(true); });
    }
  }
}

void FingerprintAuthenticator::emitStatus(const std::string& message, bool isError) {
  if (m_onStatus) {
    m_onStatus(message, isError);
  }
}
