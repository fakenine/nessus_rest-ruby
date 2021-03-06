lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name = 'nessus_rest'
  spec.homepage = 'https://github.com/kost/nessus_rest-ruby'
  spec.license = 'MIT'
  spec.summary = 'Communicate with Nessus Scanner (version 6+) over REST/JSON interface'
  spec.description = 'Ruby library for Nessus (version 6+) JSON/REST interface. This library is used for communication with Nessus over REST interface. You can start, stop, pause and resume scan. Watch progress and status of scan, download report, etc. '
  spec.email = 'vlatko.kosturjak@gmail.com'
  spec.authors = ['Vlatko Kosturjak']
  spec.version = File.exist?('VERSION') ? File.read('VERSION') : ''

  spec.files         = `git ls-files`.split($INPUT_RECORD_SEPARATOR)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '>= 1.1'
  spec.add_development_dependency 'pry'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec', '~> 3.7'
  spec.add_development_dependency 'rubocop', '~> 0.51'
  spec.add_development_dependency 'yard'
end
