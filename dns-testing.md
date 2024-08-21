1. query datapay.co.nz, this has a couple TXT records
```
dnsget datapay.co.nz -t TXT

datapay.co.nz. TXT "5dqrhshk2imotqeouft7onl10l"
datapay.co.nz. TXT "v=spf1 include:sendgrid.info ~all"
```

1. query events.datapay.co.nz, this has a TXT record set up in azure
```
dnsget events.datapay.co.nz -t TXT

dnsget: unable to lookup TXT record for events.datapay.co.nz: valid domain but no data of requested type
```

1. query events.datapay.co.nz, this has a TXT record set up in azure
```
dnsget sandbox.events.datapay.co.nz -t TXT

dnsget: unable to lookup TXT record for sandbox.events.datapay.co.nz: domain name does not exist
```

1. query test1.events.datapay.co.nz (an A record)
```
dnsget test1.events.datapay.co.nz
test1.events.datapay.co.nz. A 127.0.0.1
```



1. query test.sandbox.api.datapay.co.nz (an A record)
```
dnsget sandbox.api.datapay.co.nz
dnsget: unable to lookup A record for sandbox.api.datapay.co.nz: domain name does not exist
```

1. sandbox.events.datapay.co.nz

```
dnsget sandbox.events.datapay.co.nz

dnsget: unable to lookup A record for sandbox.events.datapay.co.nz: domain name does not exist

dnsget sandbox.events.datapay.co.nz -t TXT

dnsget: unable to lookup TXT record for sandbox.events.datapay.co.nz: domain name does not exist
```