import trustme

# Create a CA
ca = trustme.CA()

# Issue a cert signed by this CA
server_cert = ca.issue_cert(u"www.good.com")

# Save the PEM-encoded data to a file
ca.cert_pem.write_to_path("GoodRootCA.pem")
server_cert.private_key_and_cert_chain_pem.write_to_path("www.good.com.pem")
