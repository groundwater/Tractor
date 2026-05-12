cask "tractor" do
  version "0.1.0"
  sha256 "674d624db6c473a5922a67e292d967dc5cf3db103d4d78ff7dcbed541dd93d0e"

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
    Tractor installs two system extensions (TractorES + TractorNE).
    Approve them once in System Settings → Privacy & Security, then run:

      sudo tractor activate
  EOS
end
