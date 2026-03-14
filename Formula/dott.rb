class Dott < Formula
  desc "Private domain search. No middlemen."
  homepage "https://github.com/yodatoshii/dott"
  version "0.1.0"

  on_macos do
    on_arm do
      url "https://github.com/yodatoshii/dott/releases/download/v#{version}/dott-aarch64-apple-darwin.tar.gz"
      sha256 "placeholder"
    end
    on_intel do
      url "https://github.com/yodatoshii/dott/releases/download/v#{version}/dott-x86_64-apple-darwin.tar.gz"
      sha256 "placeholder"
    end
  end

  on_linux do
    url "https://github.com/yodatoshii/dott/releases/download/v#{version}/dott-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "placeholder"
  end

  def install
    bin.install "dott"
  end

  test do
    assert_match "dott", shell_output("#{bin}/dott --help")
  end
end
