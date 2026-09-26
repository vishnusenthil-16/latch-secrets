# Run with: HOMEBREW_DEVELOPER=1 brew ruby scripts/check_homebrew.rb BUNDLE
# Exercise the real formula hooks in a temporary prefix, without installing a tap,
# changing the user's Cellar, or activating a LaunchAgent.
require "formula"
require "formulary"
require "utils/gem_setup"
# Homebrew moved gem setup out of its top-level module. Support both layouts.
gem_setup = defined?(Utils::GemSetup) ? Utils::GemSetup : Homebrew
gem_setup.install_bundler_gems!(groups: ["formula_test"], setup_path: false)
require "formula_assertions"
require "extend/ENV"
require "tmpdir"
require "json"
require "digest"
require "uri"

bundle = Pathname(ARGV.fetch(0)).realpath
metadata = JSON.parse((bundle/"release.json").read)
archive_name = "latch-secrets-#{metadata.fetch("version")}.tar.gz"
raise "Invalid archive name" unless archive_name.match?(/\Alatch-secrets-\d+\.\d+\.\d+\.tar\.gz\z/)
archive = bundle/archive_name
raise "Archive checksum mismatch" unless Digest::SHA256.file(archive).hexdigest == metadata.fetch("sha256")

Dir.mktmpdir("latch-homebrew-check-") do |temporary|
  root = Pathname(temporary)
  formula_path = root/"latch-secrets.rb"
  source = (bundle/"Formula/latch-secrets.rb").read
  # Only the validation copy points at the local archive; the output formula
  # retains its immutable-version release URL.
  local_url = "file://#{URI::DEFAULT_PARSER.escape(archive.to_s)}"
  raise "Expected one formula URL" unless source.scan(/^  url /).length == 1
  formula_path.write(source.sub(/^  url .*$/, "  url #{local_url.dump}"))
  formula = Formulary.factory(formula_path)
  prefix = root/"prefix"
  formula.define_singleton_method(:prefix) { |_version = nil| prefix }
  formula.define_singleton_method(:logs) { root/"logs" }
  # brew ruby starts with a restricted PATH. Use the invoking toolchain for this
  # isolated developer check; a normal brew install supplies its Rust dependency.
  ENV["PATH"] = ENV.fetch("HOMEBREW_PATH", ENV.fetch("PATH"))
  ENV["RUSTUP_HOME"] ||= File.join(ENV.fetch("HOME"), ".rustup")
  ENV["CARGO_HOME"] = (root/"cargo").to_s
  ENV.activate_extensions!(env: "std")
  formula.brew do
    formula.fetch
    formula.install
  end
  raise "Skill was not installed" unless (prefix/"share/latch-secrets/skills/latch/SKILL.md").file?
  formula.extend(Homebrew::Assertions)
  formula.run_test
  puts "Homebrew formula fetch, install and test hooks passed in an isolated prefix."
end
