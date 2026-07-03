<?xml version="1.0" encoding="UTF-8"?>
<!-- Template de LaunchAgent para o daemon local do claude-guardian (macOS).
     Placeholders __NODE__/__REPO__ são substituídos pelo install-agent.sh.
     Instalado em /Library/LaunchAgents (root/MDM) ou ~/Library/LaunchAgents. -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.claude-guardian.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>__NODE__</string>
    <string>--experimental-strip-types</string>
    <string>__REPO__/src/cli/index.ts</string>
    <string>serve</string>
  </array>
  <key>WorkingDirectory</key>
  <string>__REPO__</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>GUARDIAN_BIND_HOST</key>
    <string>127.0.0.1</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
