Pod::Spec.new do |s|
  s.name         = "TrustKit"
  s.version      = "1.1.1"
  s.summary      = 'TrustKit is an open source framework that makes it easy to deploy SSL pinning in any iOS or OS X App.'
  s.homepage     = "https://datatheorem.github.io/TrustKit"
  s.documentation_url = 'https://datatheorem.github.io/TrustKit/documentation/'
  s.license      = { :type => 'MIT', :file => 'LICENSE' }
  s.authors      = 'Alban Diquet', 'Angela Chow', 'Eric Castro'
  s.source       = { :git => "https://github.com/datatheorem/TrustKit.git", :tag => "#{s.version}" }
  s.ios.deployment_target = '7.0'
  s.osx.deployment_target = '10.9'
  s.source_files = 'TrustKit', 'TrustKit/**/*.{h,m}', 'TrustKit/Dependencies/fishhook/*.{h,c}'
  s.public_header_files = 'TrustKit/TrustKit.h', 'TrustKit/Pinning/TSKPinVerifier.h'
  s.frameworks = 'Foundation', 'Security'
  s.vendored_libraries = 'TrustKit/Dependencies/domain_registry/*.a'
  s.requires_arc = true
end
