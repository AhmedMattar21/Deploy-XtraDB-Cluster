# Deploy-XtraDB-Cluster

## Manual Deploying


**Environment**

| Node      | IP 			   | 
| --------  | -----------------|
| pxc-n1 	| 192.168.1.161    |
| pxc-n2 	| 192.168.1.162    |
| pxc-n3    | 192.168.1.163    |
| haproxy	| 192.168.1.160	   |


### Installing XtraDB Cluster

- Disable Firewall or allow ports [3306,4444,4567,4568]

```
$ ufw disable
$ ufw status
```

```

# Allow port HERE

```

**3306**: is used for mysql client connections and SST (State Snapshot transfer) via mysqldump.


**4444**: is used for SST via Percona XtraBackup.


**4567**: is used for write-set replication traffic (over TCP) and multicast replication (over TCP and UDP).

**4568**: is used for IST (Incremental State Transfer).



- update the system

```
$ sudo apt update
```

- Install the necessary packages
```
$ sudo apt install -y wget gnupg2 lsb-release curl
```


- Configure 3 Nodes, HAProxy, and the Host with DNS Recoreds.

```
$ sudo nano /etc/hosts
192.168.1.160 hp
192.168.1.161 pxc-n1
192.168.1.162 pxc-n2
192.168.1.163 pxc-n3
```


- Download the repository package

```
$ wget https://repo.percona.com/apt/percona-release_latest.generic_all.deb
```

- Install the package with dpkg

```
$ sudo dpkg -i percona-release_latest.generic_all.deb
```

- Refresh the local cache to update the package information

```
$ apt update
```

- Enable the release repository for Percona XtraDB Cluster

```
$ sudo percona-release setup pxc80
```

- Install the cluster

```
$ sudo apt install -y percona-xtradb-cluster
```


### Configuring the first node


- Edit /etc/mysql/mysql.conf.d/mysql.cfg

```
# Template my.cnf for PXC
# Edit to your requirements.
[client]
socket=/var/run/mysqld/mysqld.sock

[mysqld]
server-id=1
datadir=/var/lib/mysql
socket=/var/run/mysqld/mysqld.sock
log-error=/var/log/mysql/error.log
pid-file=/var/run/mysqld/mysqld.pid
pxc-encrypt-cluster-traffic=OFF

# Binary log expiration period is 604800 seconds, which equals 7 days
binlog_expire_logs_seconds=604800

######## wsrep ###############
# Path to Galera library
wsrep_provider=/usr/lib/galera4/libgalera_smm.so

# Cluster connection URL contains IPs of nodes
#If no IP is found, this implies that a new cluster needs to be created,
#in order to do that you need to bootstrap this node
wsrep_cluster_address=gcomm://192.168.1.161,192.168.1.162,192.168.1.163

# In order for Galera to work correctly binlog format should be ROW
binlog_format=ROW

# Slave thread to use
wsrep_slave_threads=8

wsrep_log_conflicts

# This changes how InnoDB autoincrement locks are managed and is a requirement for Galera
innodb_autoinc_lock_mode=2

# Node IP address
wsrep_node_address=192.168.1.161
# Cluster name
wsrep_cluster_name=pxc-cluster

#If wsrep_node_name is not specified,  then system hostname will be used
wsrep_node_name=pxc-n1

#pxc_strict_mode allowed values: DISABLED,PERMISSIVE,ENFORCING,MASTER
pxc_strict_mode=ENFORCING

# SST method
wsrep_sst_method=xtrabackup-v2

```


- Important parts

```
pxc-encrypt-cluster-traffic=OFF
```

```
wsrep_cluster_address=gcomm://192.168.1.161,192.168.1.162,192.168.1.163

# Node IP address
wsrep_node_address=192.168.1.161
# Cluster name
wsrep_cluster_name=pxc-cluster

#If wsrep_node_name is not specified,  then system hostname will be used
wsrep_node_name=pxc-n1

```


- Bootstrap the first node

```
$ systemctl start mysql@bootstrap.service
```

> Bootstrap makes galera initilize the cluster.


**Important Note**
You can use mysql in the first node with this line empty.
```
wsrep_cluster_address=gcomm://
```
then join other nodes after that fill it again.

**if this line is empty you will not be able to start the service after a restart or rebooting.**



- Check cluster status.

```
$ mysql -uroot -p

mysql> show status like 'wsrep%';
```


### Configuring other node

```
$ sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
```

```
[mysqld]
pxc-encrypt-cluster-traffic=OFF

wsrep_cluster_name=pxc-cluster
wsrep_cluster_address=gcomm://192.168.70.61,192.168.70.62,192.168.70.63
wsrep_node_name=pxc2
wsrep_node_address=192.168.70.62
```


- Start MySQL

```
$ sudo systemctl start mysql
```


- check the cluster status

```
$ mysql -uroot -p

mysql> show status like '%wsrep_clustre_size%';
```


- Add user to mysql to use it for external access.

```
mysql> CREATE USER 'sammy'@'localhost' IDENTIFIED BY 'password';

mysql> GRANT ALL PRIVILEGES ON *.* TO 'sammy'@'localhost' WITH GRANT OPTION;
```


- Test the connectivity using MySQL Workbench



## Configuring HAProxy

### Preparing nodes to accept HAProxy checks.

- Install xinetd service

```
$ sudo apt install xinetd
```

- Edit/Create this file /etc/xinetd.d/mysqlchk 
```
# default: on
# description: mysqlchk

service mysqlchk
{
# this a config for xinetd, place it in /etc/xinetd.d/
	disable = no
	flags		= REUSE
	socket_type	= stream
	port		= 9200
	wait		= no
	user		= nobody
	server		= /usr/bin/clustercheck
	log_on_failure	+= USERID
	per_source	= UNLIMITED

}
```


- Add mysql user to use with Clustercheck

```
mysql> CREATE USER 'test_user'@'%' IDENTIFIED by 'ASD@123@asd';
mysql> GRANT PROCESS ON *.* TO 'test_user'@'%' IDENTIFIED BY 'ASD@123@asd';
```

- Add another user for HAProxy

```
mysql> CREATE USER 'haproxy'@'%' IDENTIFIED WITH mysql_native_password by 'ASD@123@asd';
```


>  in Percona XtraDB Cluster 8.0, the default authentication plugin is caching_sha2_password. HAProxy does not support this authentication plugin. Create a mysql user using the mysql_native_password authentication plugin.


- Edit /usr/bin/clustercheck

```
#!/bin/bash 
#
# Script to make a proxy (ie HAProxy) capable of monitoring Percona XtraDB Cluster nodes properly
#
# Authors:
# Raghavendra Prabhu <raghavendra.prabhu@percona.com>
# Olaf van Zandwijk <olaf.vanzandwijk@nedap.com>
#
# Based on the original script from Unai Rodriguez and Olaf (https://github.com/olafz/percona-clustercheck)
#
# Grant privileges required:
# GRANT PROCESS ON *.* TO 'clustercheckuser'@'localhost' IDENTIFIED BY 'clustercheckpassword!';

if [[ $1 == '-h' || $1 == '--help' ]];then
    echo "Usage: $0 <user> <pass> <available_when_donor=0|1> <log_file> <available_when_readonly=0|1> <defaults_extra_file>"
    exit
fi

MYSQL_USERNAME="test_user" 
MYSQL_PASSWORD="ASD@123@asd" 
AVAILABLE_WHEN_DONOR=0
ERR_FILE="/dev/null" 
AVAILABLE_WHEN_READONLY=${5:-1}
DEFAULTS_EXTRA_FILE=${6:-/etc/my.cnf}
#Timeout exists for instances where mysqld may be hung
TIMEOUT=10

EXTRA_ARGS=""
if [[ -n "$MYSQL_USERNAME" ]]; then
    EXTRA_ARGS="$EXTRA_ARGS --user=${MYSQL_USERNAME}"
fi
if [[ -n "$MYSQL_PASSWORD" ]]; then
    EXTRA_ARGS="$EXTRA_ARGS --password=${MYSQL_PASSWORD}"
fi
if [[ -r $DEFAULTS_EXTRA_FILE ]];then 
    MYSQL_CMDLINE="mysql --defaults-extra-file=$DEFAULTS_EXTRA_FILE -nNE --connect-timeout=$TIMEOUT \
                    ${EXTRA_ARGS}"
else 
    MYSQL_CMDLINE="mysql -nNE --connect-timeout=$TIMEOUT ${EXTRA_ARGS}"
fi
#
# Perform the query to check the wsrep_local_state
#
PXC_NODE_STATUS=($($MYSQL_CMDLINE -e "SHOW STATUS LIKE 'wsrep_local_state';SHOW VARIABLES LIKE 'pxc_maint_mode';SHOW GLOBAL STATUS LIKE 'wsrep_cluster_status';" \
     2>${ERR_FILE} | grep -A 1 -E 'wsrep_local_state$|pxc_maint_mode$|wsrep_cluster_status$' | sed -n -e '2p' -e '5p' -e '8p' | tr '\n' ' '))

# ${PXC_NODE_STATUS[0]} - wsrep_local_state
# ${PXC_NODE_STATUS[1]} - pxc_maint_mode
# ${PXC_NODE_STATUS[2]} - wsrep_cluster_status

if [[ ${PXC_NODE_STATUS[2]} == 'Primary' &&  ( ${PXC_NODE_STATUS[0]} -eq 4 || \
    ( ${PXC_NODE_STATUS[0]} -eq 2 && ${AVAILABLE_WHEN_DONOR} -eq 1 ) ) \
    && ${PXC_NODE_STATUS[1]} == 'DISABLED' ]];
then 

    # Check only when set to 0 to avoid latency in response.
    if [[ $AVAILABLE_WHEN_READONLY -eq 0 ]];then
        READ_ONLY=$($MYSQL_CMDLINE -e "SHOW GLOBAL VARIABLES LIKE 'read_only';" \
                    2>${ERR_FILE} | tail -1 2>>${ERR_FILE})

        if [[ "${READ_ONLY}" == "ON" ]];then 
            # Percona XtraDB Cluster node local state is 'Synced', but it is in
            # read-only mode. The variable AVAILABLE_WHEN_READONLY is set to 0.
            # => return HTTP 503
            # Shell return-code is 1
            echo -en "HTTP/1.1 503 Service Unavailable\r\n" 
            echo -en "Content-Type: text/plain\r\n" 
            echo -en "Connection: close\r\n" 
            echo -en "Content-Length: 43\r\n" 
            echo -en "\r\n" 
            echo -en "Percona XtraDB Cluster Node is read-only.\r\n" 
            sleep 0.1
            exit 1
        fi

    fi
    # Percona XtraDB Cluster node local state is 'Synced' => return HTTP 200
    # Shell return-code is 0
    echo -en "HTTP/1.1 200 OK\r\n" 
    echo -en "Content-Type: text/plain\r\n" 
    echo -en "Connection: close\r\n" 
    echo -en "Content-Length: 40\r\n" 
    echo -en "\r\n" 
    echo -en "Percona XtraDB Cluster Node is synced.\r\n" 
    sleep 0.1
    exit 0
else 
    # Percona XtraDB Cluster node local state is not 'Synced' => return HTTP 503
    # Shell return-code is 1
    echo -en "HTTP/1.1 503 Service Unavailable\r\n" 
    echo -en "Content-Type: text/plain\r\n" 
    echo -en "Connection: close\r\n" 
    echo -en "Content-Length: 57\r\n" 
    echo -en "\r\n" 
    echo -en "Percona XtraDB Cluster Node is not synced or non-PRIM. \r\n" 
    sleep 0.1
    exit 1
fi 
```


Just Edit this part
```
MYSQL_USERNAME="test_user" 
MYSQL_PASSWORD="ASD@123@asd" 
AVAILABLE_WHEN_DONOR=0
ERR_FILE="/dev/null" 
AVAILABLE_WHEN_READONLY=${5:-1}
DEFAULTS_EXTRA_FILE=${6:-/etc/my.cnf}
#Timeout exists for instances where mysqld may be hung
TIMEOUT=10
```


- append this line to /etc/services

```
mysqlchk        9200/tcp			 # mysqlchk
```


- Restart Xinetd service

```
$ sudo systemctl restart xinetd.service
```

it should has one service running.. (mysqlchk)

- Verify listening tcp port(9200) 
```
$ netstat -nlt
```

- if you have enabled iptable firewall, then allow port 9200.

- if the port is open and in listen state, install the telnet and try to telnet.

```
$ sudo apt install telnet

$ telnet 127.0.0.1 9200
```


- if xinetd is working, you should see the http response.
- if not, execute /usr/bin/clustercheck

- Add x permision for others on mysql dirs

```
$ sudo chmod o+x /usr/bin/mysql
$ sudo chmod o+x /var/run/mysql
```


- After configuring the HAProxy try to connect it using MySQL workbench



### Configuring HAProxy


- Edit /etc/haproxy/haproxy.cfg

```
global
	log /dev/log	local0
	log /dev/log	local1 notice
	chroot /var/lib/haproxy
	stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
	stats timeout 30s
	user haproxy
	group haproxy
	daemon

	# Default SSL material locations
	ca-base /etc/ssl/certs
	crt-base /etc/ssl/private

	# See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.3&config=intermediate
        ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
        ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
        ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
	log	global
	mode	http
	option	httplog
	option	dontlognull
        timeout connect 5000
        timeout client  50000
        timeout server  50000
	errorfile 400 /etc/haproxy/errors/400.http
	errorfile 403 /etc/haproxy/errors/403.http
	errorfile 408 /etc/haproxy/errors/408.http
	errorfile 500 /etc/haproxy/errors/500.http
	errorfile 502 /etc/haproxy/errors/502.http
	errorfile 503 /etc/haproxy/errors/503.http
	errorfile 504 /etc/haproxy/errors/504.http

frontend pxc-front
	bind 0.0.0.0:3306
	mode tcp
	default_backend pxc-back

backend pxc-back
	mode tcp
	balance leastconn
	option httpchk
	server pxc-n1 192.168.1.161:3306 check port 9200 inter 12000 rise 3 fall 3
	server pxc-n2 192.168.1.162:3306 check port 9200 inter 12000 rise 3 fall 3 
	server pxc-n3 192.168.1.163:3306 check port 9200 inter 12000 rise 3 fall 3
```

- restart haproxy service

```
$ systemctl restart haproxy.service
```




## Cluster Security

### Restrict Access to Percona Cluster
To restrict access to Percona XtraDB Cluster ports using iptables, you need to append new rules to the INPUT chain on the filter table. In the following example, the trusted range of IP addresses is 192.168.0.1/24. It is assumed that only Percona XtraDB Cluster nodes and clients will connect from these IPs. To enable packet filtering, run the commands as root on each Percona XtraDB Cluster node.

```
$ iptables --append INPUT --in-interface eth0 \
--protocol tcp --match tcp --dport 3306 \
--source 192.168.0.1/24 --jump ACCEPT
$ iptables --append INPUT --in-interface eth0 \
--protocol tcp --match tcp --dport 4444 \
--source 192.168.0.1/24 --jump ACCEPT
$ iptables --append INPUT --in-interface eth0 \
--protocol tcp --match tcp --dport 4567 \
--source 192.168.0.1/24 --jump ACCEPT
$ iptables --append INPUT --in-interface eth0 \
--protocol tcp --match tcp --dport 4568 \
--source 192.168.0.1/24 --jump ACCEPT
$ iptables --append INPUT --in-interface eth0 \
--protocol udp --match udp --dport 4567 \
--source 192.168.0.1/24 --jump ACCEPT

```

If the trusted IPs are not in sequence, you will need to run these commands for each address on each node. In this case, you can consider to open all ports between trusted hosts. This is a little bit less secure, but reduces the amount of commands. For example, if you have three Percona XtraDB Cluster nodes, you can run the following commands on each one:

```
$ iptables --append INPUT --protocol tcp \
--source 64.57.102.34 --jump ACCEPT
$ iptables --append INPUT --protocol tcp \
--source 193.166.3.20  --jump ACCEPT
$ iptables --append INPUT --protocol tcp \
--source 193.125.4.10  --jump ACCEPT
```


- Don't forget to save changes in iptables
```
$ service save iptables
```




### Enxript PXC traffic

There are two kinds of traffic in Percona XtraDB Cluster:

- Client-server traffic (the one between client applications and cluster nodes),


- Replication traffic, that includes SST, IST, write-set replication, and various service messages.


#### Client-Server encryption

Percona XtraDB Cluster uses the underlying MySQL encryption mechanism to secure communication between client applications and cluster nodes.


MySQL generates default key and certificate files and places them in the data directory. You can override auto-generated files with manually created ones.


The auto-generated files are suitable for automatic SSL configuration, but you should use the same key and certificate files on all nodes.


```
[mysqld]
ssl-ca=/etc/mysql/certs/ca.pem
ssl-cert=/etc/mysql/certs/server-cert.pem
ssl-key=/etc/mysql/certs/server-key.pem

[client]
ssl-ca=/etc/mysql/certs/ca.pem
ssl-cert=/etc/mysql/certs/client-cert.pem
ssl-key=/etc/mysql/certs/client-key.pem
```

Copy these files from ```/var/lib/mysql``` to ```/etc/mysql/certs/```
for example.

the client only needs the second part.

**Do not forget to give mysql access to the dir and certs in it**

```
root@server:/etc/mysql# chmod 500 /etc/mysql/certs/
root@server:/etc/mysql# chmod 400 /etc/mysql/certs/*
root@server:/etc/mysql# chown -R mysql:mysql /etc/mysql/certs/
```



and Enable Cluster encryption if u disabled it.

```
$ pxc-encrypt-cluster-traffic=ON
```

#### Encrypt replication traffic

its automaticlly configured when u enable traffic encription.
	
```
$ pxc-encrypt-cluster-traffic=ON
```

Replication traffic refers to the inter-node traffic which includes the SST traffic, IST traffic, and replication traffic.




#### Create your own Certs

- Generate CA key file

```
$ openssl genrsa 2048 > ca-key.pem
```

- Generate CA certification file

```
$ openssl req -new -x509 -nodes -days 3600 -key ca-key.pem -out ca.pem
```

- Generate server key

```
$ openssl req -newkey rsa:2048 -days 3600 \ 
	-nodes -keyout server-key.pem -out server-req.pem
```

- Remove the passphrase

```
$ openssl rsa -in server-key.pem -out server-key.pem
```

- Generate the server certificate file

```
$ openssl x509 -req -in server-req.pem -days 3600 \
    -CA ca.pem -CAkey ca-key.pem -set_serial 01 \
    -out server-cert.pem
```

- Generate the client key file

```
$ openssl req -newkey rsa:2048 -days 3600 \
    -nodes -keyout client-key.pem -out client-req.pem
```

- Remove the passphrase

```
$ openssl rsa -in client-key.pem -out client-key.pem
```

- Generate the client certificate file

```
$ openssl x509 -req -in client-req.pem -days 3600 \
   -CA ca.pem -CAkey ca-key.pem -set_serial 01 \
   -out client-cert.pem
```


- To verify that the server and client certificates are correctly signed by the CA certificate

```
$ openssl verify -CAfile ca.pem server-cert.pem client-cert.pem
```

If the verification is successful.

```
server-cert.pem: OK
client-cert.pem: OK
```














