#Paths
Db: "/mnt/volume2/data"
Index: "/mnt/volume2/index"
Log: "/mnt/volume1/logs"

CertificateFile: /mnt/volume1/certs/fullchain.pem
CertificatePrivateKeyFile: /mnt/volume1/certs/privkeyrsa.key
TrustedRootCertificatesPath: /etc/ssl/certs
CertificateReservedNodeCommonName: "*.sandbox.events.datapay.co.nz"

# Network configuration
HttpPort: 2113
IntTcpPort: 1112
EnableAtomPubOverHTTP: true

# Projections configuration
RunProjections: All
StartStandardProjections: true
LeaderElectionTimeoutMs: 5000

#Cluster gossip
ClusterSize: 3
DiscoverViaDns: true
ClusterDns: esdbcluster.sandbox.events.datapay.co.nz

#Logging
LogFileSize: 209715200
LogFileInterval: Day
LogFileRetentionCount: 31