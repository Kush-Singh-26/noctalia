#pragma once

#include "core/timer_manager.h"

#include <functional>
#include <memory>
#include <string>

class SystemBus;

namespace sdbus {
  class IProxy;
}

class FingerprintAuthenticator {
public:
  using AuthenticatedCallback = std::function<void()>;
  using StatusCallback = std::function<void(const std::string& message, bool isError)>;

  explicit FingerprintAuthenticator(SystemBus& bus);
  ~FingerprintAuthenticator();

  FingerprintAuthenticator(const FingerprintAuthenticator&) = delete;
  FingerprintAuthenticator& operator=(const FingerprintAuthenticator&) = delete;

  void setAuthenticatedCallback(AuthenticatedCallback callback);
  void setStatusCallback(StatusCallback callback);

  void start();
  void stop();

private:
  using DeviceReadyCallback = std::function<void(bool ready)>;

  // Async GetDefaultDevice with timeout: answers as health probe on wake and supplies the
  // proxy for verify. Never blocks the UI thread, even when fprintd is wedged mid-storm.
  void ensureDeviceProxyAsync(DeviceReadyCallback done);
  void attachDeviceSignals();
  void claimDevice();
  void startVerify(bool isRetry);
  void stopVerify();
  void releaseDevice();
  void handleVerifyStatus(const std::string& result, bool done);
  void emitStatus(const std::string& message, bool isError);
  // Chained-failure accounting: consecutive failures (probe/claim/verify-start/churn) back off
  // restarts and eventually disarm fingerprint for the session instead of churning forever.
  void noteFailure();
  void noteSuccess();
  std::chrono::milliseconds restartBackoff() const;

  SystemBus& m_bus;
  std::unique_ptr<sdbus::IProxy> m_loginManager;
  std::unique_ptr<sdbus::IProxy> m_manager;
  std::unique_ptr<sdbus::IProxy> m_device;

  AuthenticatedCallback m_onAuthenticated;
  StatusCallback m_onStatus;

  Timer m_retryTimer;

  bool m_active = false;
  bool m_verifying = false;
  bool m_claiming = false;
  bool m_sleeping = false;
  bool m_abort = false;
  bool m_reclaimAttempted = false;
  bool m_unavailable = false;
  int m_retries = 0;
  int m_consecutiveFailures = 0;
  int m_generation = 0;
};
