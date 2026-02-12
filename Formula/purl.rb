class Purl < Formula
  desc "A curl-esque CLI for making HTTP requests that require payment. Designed for humans and agents alike."
  homepage "https://purl.dev"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/stripe/purl/releases/download/v0.1.0/purl-darwin-arm64"
      sha256 "0d3b058ac79a1f6d59bd5b8251a77750cb7fa4f7e956f3b0062d3238a1a15d57"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/stripe/purl/releases/download/v0.1.0/purl-linux-amd64"
      sha256 "21476a9bd0d455b86b75cd5292e6f28bf91694d94832c7b5059ea3f55881eea4"
    end
  end

  def install
    if OS.mac? && Hardware::CPU.arm?
      bin.install "purl-darwin-arm64" => "purl"
    elsif OS.linux? && Hardware::CPU.intel?
      bin.install "purl-linux-amd64" => "purl"
    end
  end

  test do
    assert_match "purl #{version}", shell_output("#{bin}/purl --version")
  end
end
