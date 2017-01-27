Pod::Spec.new do |s|
  s.name         = "TrustKit"
  s.version      = "1.4.1"
  s.summary      = 'TrustKit is an open source framework that makes it easy to deploy SSL pinning in any iOS, macOS, tvOS or watchOS App.'
  s.homepage     = "https://datatheorem.github.io/TrustKit"
  s.documentation_url = 'https://datatheorem.github.io/TrustKit/documentation/'
  s.license      = { :type => 'MIT', :file => 'LICENSE' }
  s.authors      = 'Alban Diquet', 'Angela Chow', 'Eric Castro'
  s.source       = { :git => "https://github.com/datatheorem/TrustKit.git", :tag => "#{s.version}" }
  s.ios.deployment_target = '7.0'
  s.osx.deployment_target = '10.9'
  s.tvos.deployment_target = '10.0'
  s.watchos.deployment_target = '3.0'
  s.source_files = 'TrustKit', 'TrustKit/**/*.{h,m,c}'
  s.header_mappings_dir = 'TrustKit'
  s.public_header_files = 'TrustKit/TrustKit.h', 'TrustKit/Pinning/TSKPinningValidator.h'
  s.frameworks = 'Foundation', 'Security'
  s.requires_arc = true
end
