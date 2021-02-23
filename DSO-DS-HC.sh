#!/bin/bash
#KERNEL=$(uname -a | awk '{print $1 $3}')
rm -f DSO-DATASTAGE.csv
currentdate=`date +%s`
MAC=$(ifconfig -a | grep ether | head -1 | awk '{print $2}')
VERSION=$(cat /etc/os-release)
IP=$(hostname -i)
DATE=$(date +%m%d%Y)
HOSTNAME=$(hostname | /usr/bin/tr '[a-z]' '[A-Z]')
#FILE="Datastage-$HOSTNAME-$DATE.csv"
FILE="DSO-DATASTAGE.csv"
DT=$(date +"%m/%d/%y %T")
DS_PATH=$(grep  dsrpc  /etc/services | awk '{print $NF}' | sed 's/DSEngine@//g' | sed "s|/Server/DSEngine|/|g")
OSTYPE=$(awk -F= '$1=="ID_LIKE" { print $2 ;}' /etc/os-release | sed 's/"//g' | tr '[a-z]' '[A-Z]')
OSVER=$(awk -F= '$1=="VERSION_ID" { print $2 ;}' /etc/os-release | sed 's/"//g')
KERNEL="$OSTYPE $OSVER"
DS_CHECK=$(grep  dsrpc  /etc/services | wc -l)
if [ "$DS_CHECK" == "0" ]
then
	echo -n "Checklist,    Scan Date / Time,       MAC ID, Host Name,      OS & OS Version,        Product & Product Version,      Check Name,     Description,    Desired Values, State,  Measured Values" >>$FILE
	echo "Uninstalled,Uninstalled,Uninstalled,Uninstalled,Uninstalled,Uninstalled,Uninstalled,Uninstalled" >>$FILE
else
	for i in $DS_PATH
	do
		DS_NAME=$(head -3 $i"Version.xml" | grep "currentVersion=" | awk '{print $4}' | sed 's/currentVersion=//')
		echo "$DS_NAME" >> out.sql

		DS_VERSION=$(cat out.sql | tr '\n' ' ' | sed 's/"//g')
		rm -f out.sql

		############# Password Requirements ###################
		echo "Checklist,    Scan Date / Time,       MAC ID, Host Name,      OS & OS Version,        Product & Product Version,      Check Name,     Description,    Desired Values, State,  Measured Values" >>$FILE

		$DS_PATH'_uninstall/versionInfo'  | grep  datastage.user.name | awk '{print $NF}' >> out.sh
		$DS_PATH'_uninstall/versionInfo'  | grep  xmeta.staging.db.username | awk '{print $NF}' >> out.sh
		$DS_PATH'_uninstall/versionInfo'  | grep  xmeta.odb.db.user.name | awk '{print $NF}' >> out.sh
		$DS_PATH'_uninstall/versionInfo'  | grep  srd.db.user.name | awk '{print $NF}' >> out.sh
		$DS_PATH'_uninstall/versionInfo'  | grep  xmeta.db.username | awk '{print $NF}' >> out.sh
		$DS_PATH'_uninstall/versionInfo'  | grep  ia.db.username | awk '{print $NF}' >> out.sh
		$DS_PATH'_uninstall/versionInfo'  | grep  db2.instance.user.name | awk '{print $NF}' >> out.sh
		INSTANCE=$($DS_PATH'_uninstall/versionInfo'  | grep  db2.instance.user.name | awk '{print $NF}')
		ID=$(cat out.sh)
		for i in $ID
		do
		{
			VAL=$(cat /etc/passwd | grep -w $i  | head -1 | awk -F : '{print $7}')

			if [ "$VAL" == "/sbin/nologin" ]
			then

				echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Password Requirements," >> $FILE
				echo -n "Password must be changed at least each 90 days.," >> $FILE
				echo -n "Expected : Make $i expiry," >> $FILE
				echo -n "PASSED," >> $FILE
				echo "$VAL" >> $FILE

			else
				PWEXPCHK=`chage -l $i |grep 'Password expires' |cut -d: -f2`
				passexp=`date -d "$PWEXPCHK" +%s`
				
				exp=`expr \( $passexp - $currentdate \)`
				
				expday=`expr \( $exp / 86400 \)`
				
				if [ "$PWEXPCHK" == "never" ]
				then
					echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Password Requirements," >> $FILE
					echo -n "Password must be changed at least each 90 days.," >> $FILE
					echo -n "Expected : Make $i expiry," >> $FILE
					echo -n "FAILED," >> $FILE
					echo "$PWEXPCHK" >> $FILE
				else
					echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Password Requirements," >> $FILE
					echo -n "Password must be changed at least each 90 days.," >> $FILE
					echo -n "Expected : Make $i expiry," >> $FILE
					if [ $expday -le 0 ]; then 
					  echo -n "FAILED," >> $FILE
					  echo "$(chage -l $i | grep "Password expires" | awk '{print $4 $6}')" >> $FILE
					else
					  echo -n "PASSED," >> $FILE
					  echo "$(chage -l $i | grep "Password expires" | awk '{print $4 $6}')" >> $FILE
					fi
				fi
			fi
		}
		done
		rm -f out.sh
		############# LOGS ###########
		LOGCHK=$(find / -name InfoSphere)
		re='^[0-9]+$'
		for i in $LOGCHK
		do
			if [ "$(stat -c "%a %n" $i"/logs" | awk '{print $1}')" == "777" ]
			then
				echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
				echo -n "No read access for general users," >> $FILE
				echo -n "Expected : chmod 755 $i/logs," >> $FILE
				echo -n "FAILED," >> $FILE
				echo "$(stat -c "%a %n" $i"/logs")" >> $FILE
				LOGFILE=$(stat -c "%a %n" $i/logs/*)
				for log in $LOGFILE
				do
					if ! [[ $log =~ $re ]] ; then
						if [ "$(awk '$1' $log)" == "777" ]
						then
							echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
							echo -n "No read access for general users," >> $FILE
							echo -n "Expected : chmod 755 $log," >> $FILE
							echo -n "FAILED," >> $FILE
							echo "$(stat -c '%a %n' $log)" >> $FILE
						else
							echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
							echo -n "No read access for general users," >> $FILE
							echo -n "Expected : chmod 755 $log," >> $FILE
							echo -n "PASSED," >> $FILE
							echo "$(stat -c '%a %n' $log)" >> $FILE
						fi
					else
						continue
					fi
				done
			else
					if [ $(ls -l $i"/logs" | wc -l) -eq "0" ]
					then
						continue
					else
						echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
						echo -n "No read access for general users," >> $FILE
						echo -n "Expected : chmod 755 $i/logs," >> $FILE
						echo -n "PASSED," >> $FILE
						echo "$(stat -c "%a %n" $i"/logs")" >> $FILE
						LOGFILE=$(stat -c "%a %n" $i/logs/*)
						for log in $LOGFILE
						do
							if ! [[ $log =~ $re ]] ; then
								if [ "$(awk '$1' $log)" == "777" ]
								then
									echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
									echo -n "No read access for general users," >> $FILE
									echo -n "Expected : chmod 755 $log," >> $FILE
									echo -n "FAILED," >> $FILE
									echo "$(stat -c '%a %n' $log)" >> $FILE
								else
									echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
									echo -n "No read access for general users," >> $FILE
									echo -n "Expected : chmod 755 $log," >> $FILE
									echo -n "PASSED," >> $FILE
									echo "$(stat -c '%a %n' $log)" >> $FILE
								fi
							else
								continue
							fi
						done
					fi
			fi
		done
		for i in $LOGCHK
		do
			if [ "$(stat -c "%a %n" $i"/logs" | awk '{print $1}')" == "777" ]
			then
				echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
				echo -n "No read access for general users," >> $FILE
				echo -n "Expected : chmod 755 $i/logs," >> $FILE
				echo -n "FAILED," >> $FILE
				echo "$(stat -c "%a %n" $i"/logs")" >> $FILE
				LOGFILE=$(stat -c "%a %n" $i/logs/*)
				for log in $LOGFILE
				do
					if ! [[ $log =~ $re ]] ; then
						if [ "$(awk '$1' $log)" == "777" ]
						then
							echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
							echo -n "No read access for general users," >> $FILE
							echo -n "Expected : chmod 755 $log," >> $FILE
							echo -n "FAILED," >> $FILE
							echo "$(stat -c '%a %n' $log)" >> $FILE
						else
							echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
							echo -n "No read access for general users," >> $FILE
							echo -n "Expected : chmod 755 $log," >> $FILE
							echo -n "PASSED," >> $FILE
							echo "$(stat -c '%a %n' $log)" >> $FILE
						fi
					else
						continue
					fi
				done
			else
					if [ $(ls -l $i"/logs" | wc -l) -eq "0" ]
					then
						continue
					else
						echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
						echo -n "No read access for general users," >> $FILE
						echo -n "Expected : chmod 755 $i/logs," >> $FILE
						echo -n "PASSED," >> $FILE
						echo "$(stat -c "%a %n" $i"/logs")" >> $FILE
						LOGFILE=$(stat -c "%a %n" $i/logs/*)
						for log in $LOGFILE
						do
							if ! [[ $log =~ $re ]] ; then
								if [ "$(awk '$1' $log)" == "777" ]
								then
									echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
									echo -n "No read access for general users," >> $FILE
									echo -n "Expected : chmod 755 $log," >> $FILE
									echo -n "FAILED," >> $FILE
									echo "$(stat -c '%a %n' $log)" >> $FILE
								else
									echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
									echo -n "No read access for general users," >> $FILE
									echo -n "Expected : chmod 755 $log," >> $FILE
									echo -n "PASSED," >> $FILE
									echo "$(stat -c '%a %n' $log)" >> $FILE
								fi
							else
								continue
							fi
						done
					fi
			fi
		done

		############# INSTALLATION DIRECTORY ##################
		INSTALLCHK=$(find / -name InformationServer)
		for i in $INSTALLCHK
		do
			if [ "$(stat -c "%a %n" $i | awk '{print $1}')" == "777" ]
			then
				echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
				echo -n "No read access for general users," >> $FILE
				echo -n "Expected : chmod 755 $i," >> $FILE
				echo -n "FAILED," >> $FILE
				echo "$(stat -c "%a %n" $i)" >> $FILE
				LOGFILE=$(stat -c "%a %n" $i/*)
				for log in $LOGFILE
				do
					if ! [[ $log =~ $re ]] ; then
						if [ "$(awk '$1' $log)" == "777" ]
						then
							echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
							echo -n "No read access for general users," >> $FILE
							echo -n "Expected : chmod 755 $log," >> $FILE
							echo -n "FAILED," >> $FILE
							echo "$(stat -c '%a %n' $log)" >> $FILE
						else
							echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
							echo -n "No read access for general users," >> $FILE
							echo -n "Expected : chmod 755 $log," >> $FILE
							echo -n "PASSED," >> $FILE
							echo "$(stat -c '%a %n' $log)" >> $FILE
						fi
					else
						continue
					fi
				done
			else
					if [ $(ls -l $i | wc -l) -eq "0" ]
					then
						continue
					else
						echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
						echo -n "No read access for general users," >> $FILE
						echo -n "Expected : chmod 755 $i/logs," >> $FILE
						echo -n "PASSED," >> $FILE
						echo "$(stat -c "%a %n" $i/logs)" >> $FILE
						LOGFILE=$(stat -c "%a %n" $i/*)
						for log in $LOGFILE
						do
							if ! [[ $log =~ $re ]] ; then
								if [ "$(awk '$1' $log)" == "777" ]
								then
									echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
									echo -n "No read access for general users," >> $FILE
									echo -n "Expected : chmod 755 $log," >> $FILE
									echo -n "FAILED," >> $FILE
									echo "$(stat -c '%a %n' $log)" >> $FILE
								else
									echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
									echo -n "No read access for general users," >> $FILE
									echo -n "Expected : chmod 755 $log," >> $FILE
									echo -n "PASSED," >> $FILE
									echo "$(stat -c '%a %n' $log)" >> $FILE
								fi
							else
								continue
							fi
						done
					fi
			fi
		done

		############ Sample applications ##############
		for i in $LOGCHK
		do
			if [ $(ls -l $i/installedApps | wc -l) -eq "0" ]
			then
				continue
			else
				SAMPLE=$(find $i/installedApps -name sample.ear | wc -l)
				if [ $SAMPLE -eq "0" ]
				then
					echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
					echo -n "There are sample applications that come with the WebSphere installation," >> $FILE
					echo -n "Expected : sample.ear must not be present under this path : $i/installedApps," >> $FILE
					echo -n "PASSED," >> $FILE
					echo "sample.ear not present" >> $FILE
				else
					echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
					echo -n "There are sample applications that come with the WebSphere installation," >> $FILE
					echo -n "Expected : sample.ear must not be present under this path : $i/installedApps," >> $FILE
					echo -n "FAILED," >> $FILE
					echo "sample.ear present" >> $FILE
				fi
			fi
		done

		############## SSL ###############
		for i in $LOGCHK
		do
			if [ $(ls -l $i/properties/ssl.client.props | wc -l) -eq "0" ]
			then
				continue
			else
				WASSSL=$(cat $i/properties/ssl.client.props| grep -i "com.ibm.ssl.protocol=TLSv1.2" | wc -l)
				if [ $WASSSL -eq "1" ]
				then
					echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Encryption," >> $FILE
					echo -n "Incomplete or mismatched settings of the Secure Protocol in WebSphere and the tiers configuration," >> $FILE
					echo -n "Expected : TLS version must be TLSv1.2 for : $i/properties/ssl.client.props," >> $FILE
					echo -n "PASSED," >> $FILE
					echo "SSL Permission is ok" >> $FILE
				else
					echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Encryption," >> $FILE
					echo -n "Incomplete or mismatched settings of the Secure Protocol in WebSphere and the tiers configuration," >> $FILE
					echo -n "Expected : Change TLS version for : $i/properties/ssl.client.props (com.ibm.ssl.protocol)," >> $FILE
					echo -n "FAILED," >> $FILE
					echo "SSL Permission is not ok" >> $FILE
				fi
			fi
		done

			INSCHK=$(su - $INSTANCE -c "db2 get dbm cfg | grep -i SSL_VERSIONS" | awk '{print $NF}')
			if [ "$INSCHK" == "TLSV12" ]
			then
				echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Encryption," >> $FILE
				echo -n "Incomplete or mismatched settings of the Secure Protocol in WebSphere and the tiers configuration," >> $FILE
				echo -n "Expected : TLS version must be TLSv1.2 for : $INSTANCE," >> $FILE
				echo -n "PASSED," >> $FILE
				echo "SSL Permission is ok" >> $FILE
			else
				echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Encryption," >> $FILE
				echo -n "Incomplete or mismatched settings of the Secure Protocol in WebSphere and the tiers configuration," >> $FILE
				echo -n "Expected : su - $INSTANCE -c 'db2 UPDATE DBM CFG using SSL_VERSIONS TLSV12'," >> $FILE
				echo -n "FAILED," >> $FILE
				echo "SSL Permission is not ok" >> $FILE
			fi
		

	   ############# DB2 Repository ############
	   for i in $INSTALLCHK
	   do
			if [ $(ls -l $i/Repos | wc -l) -eq "0" ]
			then
				continue
			else
				if [ "$(stat -c "%a %n" $i/Repos | awk '{print $1}')" == "777" ]
				then
					echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
					echo -n "No read access for general users," >> $FILE
					echo -n "Expected : chmod 755 $i," >> $FILE
					echo -n "FAILED," >> $FILE
					echo "$(stat -c "%a %n" $i/Repos)" >> $FILE
					LOGFILE=$(stat -c "%a %n" $i/Repos/*)
					for log in $LOGFILE
					do
						if ! [[ $log =~ $re ]] ; then
							if [ "$(awk '$1' $log)" == "777" ]
							then
								echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
								echo -n "No read access for general users," >> $FILE
								echo -n "Expected : chmod 755 $log," >> $FILE
								echo -n "FAILED," >> $FILE
								echo "$(stat -c '%a %n' $log)" >> $FILE
							else
								echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
								echo -n "No read access for general users," >> $FILE
								echo -n "Expected : chmod 755 $log," >> $FILE
								echo -n "PASSED," >> $FILE
								echo "$(stat -c '%a %n' $log)" >> $FILE
							fi
						else
							continue
						fi
					done
				else
						if [ $(ls -l $i/Repos | wc -l) -eq "0" ]
						then
							continue
						else
							echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
							echo -n "No read access for general users," >> $FILE
							echo -n "Expected : chmod 755 $i/Repos," >> $FILE
							echo -n "PASSED," >> $FILE
							echo "$(stat -c "%a %n" $i/Repos)" >> $FILE
							LOGFILE=$(stat -c "%a %n" $i/Repos/*)
							for log in $LOGFILE
							do
								if ! [[ $log =~ $re ]] ; then
									if [ "$(awk '$1' $log)" == "777" ]
									then
										echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
										echo -n "No read access for general users," >> $FILE
										echo -n "Expected : chmod 755 $log," >> $FILE
										echo -n "FAILED," >> $FILE
										echo "$(stat -c '%a %n' $log)" >> $FILE
									else
										echo -n "DSO-DATASTAGE,$DT,$MAC,$HOSTNAME,$KERNEL,DATASTAGE $DS_VERSION,Protecting Resources - OSRs," >> $FILE
										echo -n "No read access for general users," >> $FILE
										echo -n "Expected : chmod 755 $log," >> $FILE
										echo -n "PASSED," >> $FILE
										echo "$(stat -c '%a %n' $log)" >> $FILE
									fi
								else
									continue
								fi
							done
						fi
				fi

			fi
		done
	done
fi	

    

