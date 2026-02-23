class Aeon < Formula
  desc "AI-native programming language compiler with formal verification — 30+ engines, 14+ languages"
  homepage "https://github.com/aeon-lang/aeon"
  url "https://github.com/aeon-lang/aeon/archive/refs/tags/v0.5.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  head "https://github.com/aeon-lang/aeon.git", branch: "main"

  depends_on "python@3.11"

  def install
    venv = virtualenv_create(libexec, "python3.11")
    venv.pip_install_and_link buildpath

    # Install dependencies
    venv.pip_install "z3-solver>=4.12.0"
    venv.pip_install "llvmlite>=0.41.0"

    # Create wrapper script
    (bin/"aeon").write <<~EOS
      #!/bin/bash
      exec "#{libexec}/bin/python3" -m aeon.cli "$@"
    EOS
  end

  test do
    # Test basic verification
    (testpath/"test.py").write <<~EOS
      def add(a: int, b: int) -> int:
          return a + b
    EOS

    output = shell_output("#{bin}/aeon check #{testpath}/test.py --deep-verify")
    assert_match "ok", output
  end
end
