#!/bin/bash
sudo sudo su - rundeck
#RD_OPTION_CLMA-- FQDN clma instance
#RD_OPTION_POLICYDES--  Policy Description
#RD_OPTION_ENTERPRISE-- FQDN enterprise instance
#RD_OPTION_REGION -- region of the server
if [[ "$RD_OPTION_REGION" == "us-east-1" ]];then
   deployments=devrls1241
   server=devrls1241srv1
fi   

if [[ "$RD_OPTION_REGION" == "us-west-1" ]];then
   deployments=devrls1241
   server=devrls1241srv1
fi   

if [[ "$RD_OPTION_REGION" == "eu-west-1" ]];then
   deployments=devrls1254
   server=devrls1254srv1
fi   

if [[ "$RD_OPTION_REGION" == "eu-central-1" ]];then
   deployments=devrls1486
   server=devrls1486srv1
fi

if [[ "$RD_OPTION_REGION" == "ap-southeast-2" ]];then
   deployments=devrls1376
   server=devrls1376srv1
fi
   
   create="/opt/coupa/bin/sand clients create --id $RD_OPTION_CLMA --name $RD_OPTION_CLMA -g \"client_credentials\" -a \"hydra coupa prd\""
   command1="sudo sudo runuser -l deploy -c '$create'"
   temp=$(cd /opt/coupa-flash/main && bundle exec rake common:swift:run_command["$deployments","$server","$command1"] NODE_FROM=rundeck|grep "Client Secret")
   if echo $temp| grep "Client Secret"
   then
       secret=$(echo $temp  | awk -F ":" '{print $2}' |cut -c 2- |tr -d \\r)
       policy="/opt/coupa/bin/sand policies create -i \"$RD_OPTION_CLMA-outbound\" -d \"$RD_OPTION_POLICYDES\" -s \"$RD_OPTION_CLMA\" -r \"coupa:enterprise:$RD_OPTION_ENTERPRISE\" -r \"coupa:enterprise:$RD_OPTION_ENTERPRISE:contract\" -r \"coupa:enterprise:$RD_OPTION_ENTERPRISE:clma\" -r \"coupa:service:esign-prd.io.coupacloud.com\" -a \"<.*>\" --allow"
       command2="sudo sudo runuser -l deploy -c '$policy'"
       cd /opt/coupa-flash/main && bundle exec rake common:swift:run_command["$deployments","$server","$command2"] NODE_FROM=rundeck
    
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null rundeck@$RD_OPTION_CLMA 'bash -s' << EOF
        sudo su - exari
        cd /mnt/data
        curl -X POST -d 'grant_type=client_credentials&scope=coupa' --user $RD_OPTION_CLMA:$secret https://sand-dev.io.coupadev.com/oauth2/token
        
        ./register-core-sso-client.sh $RD_OPTION_ENTERPRISE $RD_OPTION_CLMA sand-dev.io.coupadev.com '$RD_OPTION_CLMA:$secret' true >output
        if cat output|grep "Success"
        then
            tdate=$(date +%F_%R)
            OIDCClientID=\$(cat output| grep OIDCClientID | cut -d " " -f 2 )
            
            OIDCClientSecret=\$(cat output| grep OIDCClientSecret | cut -d " " -f 2 )
        
            cp /mnt/data/apache/ssl/ssl.conf /mnt/data/apache/ssl/ssl.conf-backup-\$tdate
            
              aws s3 cp s3://exari-installers/sso-integration/OIDC .
                sed -i "s/<ID>/\$OIDCClientID/" OIDC
                sed -i "s/<SECRET>/\$OIDCClientSecret/" OIDC
                sed -i "s|<MetaURL>|https://$RD_OPTION_ENTERPRISE/.well-known/openid-configuration|" OIDC
                sed -i "s|<RedirectURL>|https://$RD_OPTION_CLMA/exaricm/redirect_uri|" OIDC
            
            if cat /mnt/data/apache/ssl/ssl.conf|grep "##odic-block-holding-point"
            then
                sed -i '/##odic-block-holding-point/r OIDC' /mnt/data/apache/ssl/ssl.conf
            else
                cp OIDC /mnt/data/apache/ssl/ssl.conf.oidc
            fi
            
            if apachectl configtest 2>&1 |grep "Syntax OK"
            then
                
                cp /mnt/data/Ent/tomcat/shared/classes/alfresco-global.properties /mnt/data/Ent/tomcat/shared/classes/alfresco-global.properties-backup-\$tdate
                if cat /mnt/data/Ent/tomcat/shared/classes/alfresco-global.properties |grep "aws.secret.name"
                then
                    name=\$(cat /mnt/data/Ent/tomcat/shared/classes/alfresco-global.properties |grep "aws.secret.name"|awk -F '=' '{print \$2}')
                    aregion=\$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)
                    SecretString=\$(aws secretsmanager get-secret-value --secret-id "prd/application/clma/sre-upgrade-test-3.clma.coupadev.com"  --region "us-east-1" --query "SecretString" --output text| jq '."sand.client.id" |="'$RD_OPTION_CLMA'"'| jq '."sand.client.secret" |="'$secret'"')
                    aws secretsmanager put-secret-value --secret-id "\$name" --region "\$aregion" --secret-string "\$SecretString"
                    
                else
                    if cat /mnt/data/Ent/tomcat/shared/classes/alfresco-global.properties |grep "<CLIENT_ID>"
                    then
                        sed -i "s|<CLIENT_ID>|$RD_OPTION_CLMA|" /mnt/data/Ent/tomcat/shared/classes/alfresco-global.properties
                        sed -i "s|<CLIENT_SECRET>|$secret|" /mnt/data/Ent/tomcat/shared/classes/alfresco-global.properties
                        sed -i "s|<TOKENT_SITE>|https://sand-dev.io.coupahost.com|" /mnt/data/Ent/tomcat/shared/classes/alfresco-global.properties
                    
                    else
                        sed -i "s|enterprise.client.id=.*|enterprise.client.id=$RD_OPTION_CLMA|" /mnt/data/Ent/tomcat/shared/classes/alfresco-global.properties
                        sed -i "s|enterprise.client.secret=.*|enterprise.client.secret=$RD_OPTION_SECRET|" /mnt/data/Ent/tomcat/shared/classes/alfresco-global.properties
                        sed -i "s|enterprise.token.site=.*|enterprise.token.site=https://sand-dev.io.coupahost.com|" /mnt/data/Ent/tomcat/shared/classes/alfresco-global.properties
                    fi
                fi
                    
                cp /mnt/data/Ent/tomcat/shared/classes/alfresco/web-extension/share-config-custom.xml /mnt/data/Ent/tomcat/shared/classes/alfresco/web-extension/share-config-custom-\$tdate.xml
                cp /mnt/data/Ent/tomcat/shared/classes/alfresco/web-extension/share-config-custom-EnterpriseSSO.xml /mnt/data/Ent/tomcat/shared/classes/alfresco/web-extension/share-config-custom.xml 
                
            else
                cp /mnt/data/apache/ssl/ssl.conf /mnt/data/apache/ssl/ssl.conf-backup-\$tdate-afterscript
                cp /mnt/data/apache/ssl/ssl.conf-backup-\$tdate /mnt/data/apache/ssl/ssl.conf
                echo "Error in ssl.conf file Check ssl-config backup"
            fi
        else
            echo "Error in executing register SSO script"
        fi
EOF
    else
        echo "DUPLICATE ENTRY remove existing credential from sand server and run the job again."
    fi