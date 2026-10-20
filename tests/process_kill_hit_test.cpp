#include "shell/process/process_panel.h"

#include <print>

namespace {

  bool expect(bool actual, bool expected, const char* message) {
    if (actual == expected)
      return true;
    std::println(stderr, "process_kill_hit_test: {}: expected {}, got {}", message, expected, actual);
    return false;
  }

} // namespace

int main() {
  constexpr float w = 720.0F;
  constexpr float h = 42.0F;
  bool ok = true;

  // Trash button: spaceSm inset from the right, controlHeightSm square, vertically centered.
  ok = expect(processKillButtonHit(w - 8.0F - 16.0F, h * 0.5F, w, h, 1.0F), true, "button center") && ok;
  ok = expect(processKillButtonHit(10.0F, h * 0.5F, w, h, 1.0F), false, "left side miss") && ok;
  ok = expect(processKillButtonHit(w - 8.0F - 16.0F, 0.0F, w, h, 1.0F), false, "above button miss") && ok;

  constexpr float w2 = 1440.0F;
  constexpr float h2 = 84.0F;
  ok = expect(processKillButtonHit(w2 - 16.0F - 32.0F, h2 * 0.5F, w2, h2, 2.0F), true, "scaled button center") && ok;
  ok = expect(processKillButtonHit(w2 - 16.0F - 32.0F, 0.0F, w2, h2, 2.0F), false, "scaled above miss") && ok;

  return ok ? 0 : 1;
}
