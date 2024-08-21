# vm
https://portal.azure.com/#@datapaysoftwaredatacomco.onmicrosoft.com/resource/subscriptions/4fec2577-2a1e-4767-a92a-262ef200ec32/resourceGroups/pacific-workload-esdb-ae-sandbox_group/providers/Microsoft.Compute/virtualMachines/pacific-workload-esdb-ae-sandbox/bastionHost
- removed public IP

New VM created pacific-workload-esdb-ae-sandbox

user: azureuser



# steps
1. ran `curl -s https://b8c71131fa86eb319fa711a865a09ad41744b11b69c58fae:@packagecloud.io/install/repositories/EventStore/EventStore-Commercial/script.deb.sh | sudo bash`
1. `sudo apt-get install eventstore-commercial=24.2.0`
1. start eventstore with `sudo systemctl start eventstore`

# config
1. config can be opened with `nano /etc/eventstore/eventstore.conf`
1. service can be modified with `nano /lib/systemd/system/eventstore.service`
    1. to run eventstore without a cert, you can add the `insecure` flag to the service like so:`ExecStart=/bin/bash -c 'echo $$ > /run/eventstore/eventstore.pid; exec /usr/bin/eventstored --insecure'`


1. view logs with `journalctl -u eventstore.service`
1. tail logs with `journalctl -u eventstore.service -f --since "now"`

1. access web interface by pasting following into terminal (vscode prompts for port forward)
`https://localhost:2113`

1. Install certbot
`sudo snap install --classic certbot`

1. Install the certbot dns azure plugin https://github.com/terricain/certbot-dns-azure
```
sudo snap install --channel=stable certbot-dns-azure
sudo snap set certbot trust-plugin-with-root=ok
sudo snap connect certbot:plugin certbot-dns-azure
```

1. configure certbot plugin

create a config file `azure.ini` with these contents:
```
dns_azure_sp_client_id = ea2f4396-7e92-4349-88ae-xxxxxxxxxxxxxxx
dns_azure_sp_client_secret = 2Nx8Q~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
dns_azure_tenant_id = 31b338e6-e34b-4cb8-bec2-xxxxxxxxxxxx
dns_azure_environment = "AzurePublicCloud"
dns_azure_zone1 = sandbox.events.datapay.co.nz:/subscriptions/4fec2577-2a1e-4767-a92a-262ef200ec32/resourceGroups/pacific-workload-rg-ae-sandbox
```
(can use `echo "pastedtexthere" > azure.ini`)

now use certbot with the plugin and config file:
`sudo certbot certonly --key-type rsa --dns-azure-config ./azure.ini -d esdb.sandbox.events.datapay.co.nz`
you will be prompted for a support email, use
`eventstore.datapay.support@datacom.com`

result:
```
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/esdb.sandbox.events.datapay.co.nz/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/esdb.sandbox.events.datapay.co.nz/privkey.pem
This certificate expires on 2024-10-29.
These files will be updated when the certificate renews.
Certbot has set up a scheduled task to automatically renew this certificate in the background.
```

1. Move certs to a different folder
```
cd /etc/letsencrypt/live/esdb.sandbox.events.datapay.co.nz/
sudo mkdir /etc/eventstore/certs
sudo cp fullchain.pem /etc/eventstore/certs/fullchain.pem
sudo cp privkey.pem /etc/eventstore/certs/privkey.pem
cd /etc/eventstore/certs
sudo chown eventstore:eventstore *
sudo chmod 600 *
```

1. Set up config file
opened for editing: `sudo nano /etc/eventstore/eventstore.conf `

contents:
```ini
# Paths
CertificateFile: /etc/eventstore/certs/fullchain.pem
CertificatePrivateKeyFile: /etc/eventstore/certs/privkey.pem
CertificateReservedNodeCommonName: "*.sandbox.events.datapay.co.nz"

# Network Config
HttpPort: 2113
IntTcpPort: 1112
EnableAtomPubOverHTTP: true
IntIp: 0.0.0.0
ExtIp: 0.0.0.0
AdvertiseHostToClientAs: esdb.sandbox.events.datapay.co.nz

# Projections config
RunProjections: All
StartStandardProjections: true
```

1. Try restart eventstore, then watch the events
```
sudo systemctl restart eventstore.service

journalctl -u eventstore.service -f --since "now"
```

# Confirm connectivity
`wget -qO- https://esdb.sandbox.events.datapay.co.nz:2113/gossip`
should respond with something like this:
```
{
  "members": [
    {
      "instanceId": "bbca637b-1780-4ba6-a6c8-e8cf25f3d040",
      "timeStamp": "2024-08-01T04:30:15.6319123Z",
      "state": "Leader",
      "isAlive": true,
      "internalTcpIp": "127.0.0.1",
      "internalTcpPort": 0,
      "internalSecureTcpPort": 1112,
      "externalTcpIp": "esdb.sandbox.events.datapay.co.nz",
      "externalTcpPort": 0,
      "externalSecureTcpPort": 0,
      "httpEndPointIp": "esdb.sandbox.events.datapay.co.nz",
      "httpEndPointPort": 2113,
      "lastCommitPosition": 20316,
      "writerCheckpoint": 20683,
      "chaserCheckpoint": 20683,
      "epochPosition": 20035,
      "epochNumber": 12,
      "epochId": "aa304edf-c9fa-4472-be32-6db2bfabad3b",
      "nodePriority": 0,
      "isReadOnlyReplica": false,
      "esVersion": "24.6.0"
    }
  ],
  "serverIp": "esdb.sandbox.events.datapay.co.nz",
  "serverPort": 2113
}
```




# parameter store values
CERTIFICATE_EMAIL (ec2-esdb-cert-email-config) = `eventstore.datapay.support@datacom.com`
DOMAIN_NAME (ec2-esdb-cert-dns-config) = `esdb.sandbox.events.datapay.co.nz`
EVENTSTORE_CONFIG (ec2-esdb-config) [file](./ec2-esdb-config.md)
CLOUDWATCH_CONFIG (ec2-esdb-cw-config) [file](./ec2-esdb-cw-config.json)




# Testing with pacific template (on cluster)
pacific-workload-aks-ae-sandbox
aks-helloworld-four

# Testing with pacific template (On azure VM)
1. az acr login -name pacificsharedservicesacreaeshared.azurecr.io


# firewall settings
For external TCP connections, open TCP 1113
