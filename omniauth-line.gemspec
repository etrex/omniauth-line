# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "omniauth-line/version"

Gem::Specification.new do |s|
  s.name        = "omniauth-line"
  s.version     = OmniAuth::Line::VERSION
  s.authors     = ["chrislintw"]
  s.email       = ["yichunlin314@gmail.com"]
  s.homepage    = "https://github.com/chrislintw/omniauth-line"
  s.description = %q{OmniAuth strategy for Line}
  s.summary     = s.description
  s.license     = "MIT"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_dependency 'json', '>= 1.8'
  s.add_dependency 'omniauth-oauth2', '>= 1.6'
  s.add_development_dependency 'bundler', '~> 1.3'

end
