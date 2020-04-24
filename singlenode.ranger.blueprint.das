{
    "configurations" : [
        {
           "hive-site": {
                "javax.jdo.option.ConnectionPassword": "hive"
            }
        },
	{
	    "core-site": {
		"hadoop.http.authentication.cookie.persistent" : "true"
	    }
	},
	{
	    "hdfs-site": {
		"dfs.namenode.safemode.extension" : "1000"
	     }
	},
        {
            "hbase-env": {
                "phoenix_sql_enabled" : "true",
                "hbase_regionserver_heapsize" : "1024"
            }
        },
        {
            "yarn-site": {
                "yarn.node-labels.enabled" : "true",
                "yarn.scheduler.maximum-allocation-mb" : "36864",
                "yarn.resourcemanager.scheduler.monitor.enable" : "true"
            }
        },
        {
            "mapred-site" : {
                "properties" : {
                    "yarn.app.mapreduce.am.resource.mb" : "2048",
                    "mapreduce.reduce.memory.mb" : "4096",
                    "mapreduce.map.memory.mb" : "4096"
                } 
            }
        },
        {
            "hive-env" : {
                "properties" : {
                    "hive_database" : "Existing MySQL Database",
                    "hive_database_name" : "hive",
                    "hive_database_password" : "hive",
                    "hive_database_type" : "mysql",
                    "hive.heapsize" : "1024",
                    "hive.metastore.heapsize" : "1024"
                 }
            }
        },
        {
            "hive-site" : {
                "properties" : {
                    "ambari.hive.db.schema.name": "hive",
                    "javax.jdo.option.ConnectionURL" : "jdbc:mysql://localhost/hive?createDatabaseIfNotExist=true",
                    "hive.tez.container.size" : "4096"
                 }
            }
        },
        {
            "tez-site" : {
                "properties" : {
                    "tez.am.resource.memory.mb" : "1024",
                    "tez.task.resource.memory.mb" : "2048"
                }
            }
        },
        {
            "admin-properties" : {
                "properties" : {
                    "DB_FLAVOR" : "MYSQL",
                    "policymgr_external_url" : "http://xxFQDNxx:6080",
                    "db_name" : "ranger",
                    "db_user" : "ranger",
                    "db_password" : "rangeradmin",
                    "db_host" : "localhost",
                    "db_root_user" : "root",
                    "db_root_password" : "admin"
                }
            }
        },
        {
            "ranger-env" : {
                "properties" : {
                    "ranger_admin_password" : "xxxADMINPWxx",
                    "admin_password": "xxxADMINPWxx",
                    "rangertagsync_user_password": "xxxADMINPWxx",
                    "rangerusersync_user_password": "xxxADMINPWxx",
                    "keyadmin_user_password": "xxxADMINPWxx",
                    "create_db_dbuser" : "true",
                    "ranger-hdfs-plugin-enabled" : "Yes",
                    "ranger-hive-plugin-enabled" : "Yes"
                }
            }
        },
        {
            "ranger-hdfs-plugin-properties" : {
                "properties" : {
                    "ranger-hdfs-plugin-enabled" : "Yes"
                }
            }
        },
        {
            "ranger-hdfs-security" : {
                "properties" : {
                    "ranger.plugin.hdfs.policy.rest.url" : "http://localhost:6080"
                }
            }
        },
        {
            "ranger-admin-site" : {
                "properties" : {
                    "ranger.audit.solr.urls" : "http://localhost:8886/solr/ranger_audits",
                    "ranger.audit.source.type" : "solr",
                    "ranger.audit.solr.username" : "ranger_solr",
                    "ranger.audit.solr.password" : "ranger"
                }
            }
        },
        {
            "ranger-admin-site" : {
                "properties" : {
                    "ranger.jpa.jdbc.driver" : "com.mysql.jdbc.Driver",
                    "ranger.jpa.jdbc.url" : "jdbc:mysql://localhost/ranger"
                }
            }
        },
        {
            "ranger-tagsync-site" : {
                "properties" : {
                    "ranger.tagsync.source.atlasrest.username" : "admin",
                    "ranger.tagsync.source.atlasrest.endpoint" : "http://localhost:21000",
                    "ranger.tagsync.dest.ranger.endpoint" : "{{ranger_external_url}}",
                    "ranger.tagsync.source.atlasrest" : "true"
                }
            }
        },
        {
            "zookeeper-env" : {
                "properties" : {
                    "zk_server_heapsize" : "512m"
                }
            }
        },
        {
            "hadoop-env" : {
                "properties" : {
                    "hadoop_heapsize" : "1024",
                    "namenode_heapsize" : "1024m",
                    "namenode_opt_maxnewsize" : "512m",
                    "namenode_opt_maxpermsize" : "512m",
                    "dtnode_heapsize" : "1536m"
                }
            }
        },
        {
            "hdfs-site" : {
                "properties" : {
                    "dfs.namenode.http-address" : "0.0.0.0:50070",
                    "dfs.replication" : "1",
                    "dfs.replication.max" : "10"
                }
            }
        },
        {
            "core-site": {
                "properties" : {
                    "hadoop.proxyuser.admin.hosts" : "*",
                    "hadoop.proxyuser.admin.groups" : "*",
                    "hadoop.proxyuser.root.hosts" : "*",
                    "hadoop.proxyuser.root.groups" : "*"
                }
            }
        },
        {
            "yarn-site": {
                "properties" : {
                    "yarn.resourcemanager.webapp.address" : "0.0.0.0:8088"
                }
            }
        },
        {
            "kafka-broker" : {
                "properties" : {
                    "offsets.topic.replication.factor" : "1"
                }
            }
        },
        {
            "spark2-env" : {
                "properties" : {
                    "spark_daemon_memory" : "512"
                }
            }
        },
        {
            "atlas-env" : {
                "properties" : {
                    "atlas.admin.password" : "xxxADMINPWxx"
                }
            }
        },
        {
            "application-properties" : {
                "properties" : {
                    "atlas.audit.hbase.zookeeper.quorum" : "xxFQDNxx:2181",
                    "atlas.graph.index.search.solr.zookeeper-url": "xxFQDNxx:2181/infra-solr",
                    "atlas.graph.storage.hostname": "xxFQDNxx",
                    "atlas.kafka.bootstrap.servers": "xxFQDNxx:6667",
                    "atlas.kafka.zookeeper.connect": "xxFQDNxx:2181"
                }
            }
        },
        {
            "ams-grafana-env": {
                "properties": {
                    "metrics_grafana_username": "admin",
                    "metrics_grafana_password": "admin"
                 }
            }
        },
        {
            "hst-server-conf" : {
                "properties" : {
                    "customer.account.name" : "ACME Corp",
                    "server.max.heap" : "512",
                    "customer.enable.flex.subscription" : "false",
                    "customer.flex.subscription.id" : "",
                    "customer.notification.email" : "example@acme.com",
                    "customer.smartsense.id" : "A-00000000-C-00000000"
                }
            }
        },
        {
            "activity-zeppelin-site" : {
                "properties" : {
                    "zeppelin.anonymous.allowed" : "true"
                }
            }
        },
        {
            "activity-zeppelin-shiro": {
                "properties": {
                    "users.admin": "admin"
                }
            }
        },
        {
            "druid-common" : {
                "properties" : {
                    "druid.metadata.storage.connector.user" : "druid",
                    "database_name" : "druid",
                    "metastore_hostname" : "localhost",
                    "druid.metadata.storage.connector.port" : "3306",
                    "druid.metadata.storage.type" : "mysql",
                    "druid.metadata.storage.connector.password" : "druid",
                    "druid.metadata.storage.connector.connectURI" : "jdbc:mysql://localhost:3306/druid?createDatabaseIfNotExist=true",
                    "druid.extensions.loadList": "[\"mysql-metadata-storage\", \"druid-datasketches\", \"druid-hdfs-storage\", \"druid-kafka-indexing-service\", \"ambari-metrics-emitter\"]",
                    "druid.storage.storageDirectory": "/user/druid/data",
                    "druid.indexer.logs.type": "hdfs",
                    "druid.indexer.logs.directory": "/user/druid/logs"
                }
            }
        },
        {
            "druid-env" : {
                "properties" : {
                    "druid.broker.jvm.heap.memory" : "2048",
                    "druid.historical.jvm.heap.memory" : "2048"
                }
            }
        },
        {
            "superset" : {
                "properties" : {
                    "SUPERSET_DATABASE_USER" : "superset",
                    "SUPERSET_DATABASE_PASSWORD" : "superset",
                    "SECRET_KEY" : "secretkey",
                    "SUPERSET_DATABASE_NAME" : "superset",
                    "SUPERSET_DATABASE_PORT" : "3306",
                    "SUPERSET_DATABASE_HOSTNAME" : "localhost",
                    "MAPBOX_API_KEY" : "",
                    "SUPERSET_DATABASE_TYPE" : "mysql"
                }
            }
        },
        {
            "superset-env" : {
                "properties" : {
                    "superset_admin_lastname" : "admin",
                    "superset_admin_email" : "root@localhost",
                    "superset_admin_firstname" : "admin",
                    "superset_admin_user" : "admin",
                    "superset_admin_password" : "xxxADMINPWxx"
                }
            }
        },
        {
            "superset" : {
                "properties" : {
                    "SUPERSET_WEBSERVER_PORT" : "9089"
                }
            }
        },
        {
            "data_analytics_studio-properties" : {
                "properties" : {
                    "content" : "application.name=das-webapp\napplication.version=1.4.4.1.4.4.0-10\ndas.jobs.dir=/user/{{data_analytics_studio_user}}/jobs\ndas.api.url={{data_analytics_studio_webapp_server_url}}\nuse.hive.interactive.mode=false"
                }
            }
        },
        {
            "data_analytics_studio-security-site" : {
                "properties" : {
                    "admin_users" : "admin"
                }
            }
        },
        {
            "data_analytics_studio-database" : {
                "properties" : {
                    "data_analytics_studio_database_port" : "5435",
                    "data_analytics_studio_database_username" : "das",
                    "data_analytics_studio_database_host" : "xxFQDNxx",
                    "das_autocreate_db" : "true",
                    "data_analytics_studio_database_name" : "das",
                    "data_analytics_studio_database_password" : "supersecret1"
                }
            }
        }
    ],
    "host_groups" : [
        {
            "name" : "all",
            "components" : [
                {
                    "name" : "PIG"
                },
                {
                    "name" : "HISTORYSERVER"
                },
                {
                    "name" : "NAMENODE"
                },
                {
                    "name" : "HBASE_MASTER"
                },
                {
                    "name" : "HBASE_REGIONSERVER"
                },
                {
                    "name" : "PHOENIX_QUERY_SERVER"
                },
                {
                    "name" : "HBASE_CLIENT"
                },
                {
                    "name" : "AMBARI_SERVER"
                },
                {
                    "name" : "APP_TIMELINE_SERVER"
                },
                {
                    "name" : "TIMELINE_READER"
                },
                {
                    "name" : "HDFS_CLIENT"
                },
                {
                    "name" : "HIVE_CLIENT"
                },
                {
                    "name" : "NODEMANAGER"
                },
                {
                    "name" : "DATANODE"
                },
                {
                    "name" : "RESOURCEMANAGER"
                },
                {
                    "name" : "ZOOKEEPER_SERVER"
                },
                {
                    "name" : "ZOOKEEPER_CLIENT"
                },
                {
                    "name" : "HIVE_SERVER"
                },
                {
                    "name" : "METRICS_COLLECTOR"
                },
                {
                    "name" : "METRICS_MONITOR"
                },
                {
                    "name" : "METRICS_GRAFANA"
                },
                {
                    "name" : "SECONDARY_NAMENODE"
                },
                {
                    "name" : "TEZ_CLIENT"
                },
                {
                    "name" : "HIVE_METASTORE"
                },
                {
                    "name" : "YARN_CLIENT"
                },
                {
                    "name" : "MAPREDUCE2_CLIENT"
                },
                {
                    "name" : "RANGER_ADMIN"
                },
                {
                    "name" : "RANGER_USERSYNC"
                },
                {
                    "name" : "RANGER_TAGSYNC"
                },
                {
                    "name" : "INFRA_SOLR"
                },
                {
                    "name" : "INFRA_SOLR_CLIENT"
                },
                {
                    "name" : "SPARK2_CLIENT"
                },
                {
                    "name" : "SPARK2_JOBHISTORYSERVER"
                },
                {
                    "name" : "SPARK2_THRIFTSERVER"
                },
                {
                    "name" : "LIVY2_SERVER"
                },
                {
                    "name" : "KAFKA_BROKER"
                },
                {
                    "name" : "ATLAS_SERVER"
                },
                {
                    "name" : "ATLAS_CLIENT"
                },
                {
                    "name" : "ACTIVITY_ANALYZER"
                },
                {
                    "name" : "ACTIVITY_EXPLORER"
                },
                {
                    "name" : "HST_SERVER"
                },
                {
                    "name" : "HST_AGENT"
                },
                {
                    "name" : "SQOOP"
                },
                {
                    "name" : "SUPERSET"
                },
                {
                    "name" : "DRUID_MIDDLEMANAGER"
                },
                {
                    "name" : "DRUID_ROUTER"
                },
                {
                    "name" : "DRUID_OVERLORD"
                },
                {
                    "name" : "DRUID_COORDINATOR"
                },
                {
                    "name" : "DRUID_BROKER"
                },
                {
                    "name" : "DRUID_HISTORICAL"
                },
                {
                    "name" : "DATA_ANALYTICS_STUDIO_EVENT_PROCESSOR"
                },
                {
                    "name" : "DATA_ANALYTICS_STUDIO_WEBAPP"
                }
                   ],
                   "cardinality" : "1"
               }
           ],
    "Blueprints" : {
        "stack_name" : "HDP",
        "stack_version" : "3.1"
    }
}
