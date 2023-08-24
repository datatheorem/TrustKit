Pod::Spec.new do |s|
  s.name         = "TrustKit"
  s.version      = "3.0.3"
  s.summary      = 'TrustKit is an open source framework that makes it easy to deploy SSL pinning in any iOS, macOS, tvOS or watchOS App.'
  s.homepage     = "https://datatheorem.github.io/TrustKit"
  s.documentation_url = 'https://datatheorem.github.io/TrustKit/documentation/'
  s.license      = { :type => 'MIT', :file => 'LICENSE' }
  s.authors      = 'Alban Diquet', 'Angela Chow', 'Eric Castro'
  s.source       = { :git => "https://github.com/datatheorem/TrustKit.git", :tag => "#{s.version}" }

  s.ios.deployment_target = '12.0'
  s.osx.deployment_target = '10.13'
  s.tvos.deployment_target = '12.0'
  s.watchos.deployment_target = '4.0'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.source_files = ['TrustKit', 'TrustKit/**/*.{h,m,c}']
  s.public_header_files = [
    'TrustKit/public/TrustKit.h',
    'TrustKit/public/TSKTrustKitConfig.h',
    'TrustKit/public/TSKPinningValidator.h',
    'TrustKit/public/TSKPinningValidatorCallback.h',
    'TrustKit/public/TSKPinningValidatorResult.h',
    'TrustKit/public/TSKTrustDecision.h',
  ]
  s.frameworks = ['Foundation', 'Security']
  s.requires_arc = true
end
