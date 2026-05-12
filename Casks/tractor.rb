cask "tractor" do
  version "0.2.0"
  sha256 "ee1e2e3ffa1d6879525e8870f66b0b785b9eeae614fc647d63b78aecc3cf375d"

  url "https://github.com/groundwater/Tractor/releases/download/v#{version}/Tractor-#{version}.pkg",
      verified: "github.com/groundwater/Tractor/"
  name "Tractor"
  desc "Real-time process and network monitor for AI coding agents"
  homepage "https://github.com/groundwater/Tractor"

  depends_on macos: ">= :sequoia"

  pkg "Tractor-#{version}.pkg"

  uninstall pkgutil:    "com.jacobgroundwater.Tractor",
            launchctl: [
              "NetworkExtension.com.jacobgroundwater.Tractor.NE",
              "3FGZQE8AW3.com.jacobgroundwater.Tractor.ES",
            ],
            delete:    [
              "/Library/Application Support/Tractor",
              "/usr/local/bin/tractor",
            ]

  zap trash: [
    "~/Library/Preferences/com.jacobgroundwater.Tractor.plist",
  ]

  caveats <<~EOS
    Tractor can activate three privileged components after install:
      1. Endpoint Security (required for `tractor trace`)
      2. Network Extension (optional, for `--net` / `--mitm`)
      3. Certificate Root (optional, for `--mitm`)

    Explicit post-install steps:

      sudo tractor activate endpoint-security
      sudo tractor activate network-extension
      sudo tractor activate certificate-root
  EOS
end
