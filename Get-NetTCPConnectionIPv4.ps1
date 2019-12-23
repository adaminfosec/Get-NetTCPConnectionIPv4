﻿function Get-NetTCPConnectionIPv4 {

<#
.SYNOPSIS
Displays listening and established connections on a computer's primary IPv4 address
.DESCRIPTION
Displays listening and established connections on a computer's primary IPv4 address
other than 0.0.0.0 and 127.0.0.1.
.PARAMETER ComputerName
One or more names or IP addresses to query.
.PARAMETER IPresolve
Specify this switch to attempt to resolve remote IP addresses to host names.
.EXAMPLE
localhost | Get-NetTCPConnectionIPv4

This command pipes the computer name to Get-NetTCPConnectionIPv4 and gets listening or
established connections.
.EXAMPLE
Get-NetTCPConnectionIPv4 -ComputerName localhost, SERVER1 -IPresolve

This command gets listening or established connections across two computers and
attemps to resovle the remote IP addresses to host names.
#>

[cmdletbinding()]
    Param (
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [Alias('hostname')]
        [string[]]$ComputerName,

        [switch]$IPresolve
    )
    Begin{}
    Process{
        foreach ($computer in $ComputerName) {
            $date = Get-Date

            $localIPv4 = Get-NetIPConfiguration

            $TCPconnections = Get-NetTCPConnection -State Established, Listen -LocalAddress $localIPv4[0].IPv4Address.IPAddress | 
                              Select-Object -Property @{l='ComputerName';e={($env:COMPUTERNAME)}}, 
                              localAddress, localPort, RemoteAddress, RemotePort, State, OwningProcess, 
                              CreationTime, @{l='ConnectionAge';e={New-TimeSpan -Start $_.CreationTime -End $date}} |
                              Where-Object -Property RemoteAddress -NE 0.0.0.0
            #Get all processes
            $processes = Get-Process

            
        
            foreach($TCPconnection in $TCPconnections) {
                $IPresolver =""
                
                
                #Match process Id to process name
                $OwningProcess = $processes | where -Property Id -EQ $TCPconnection.OwningProcess

                #Assign the port name
                $portName = ""
                switch ($TCPconnection.RemotePort) {
                    443{$portName = 'HTTPS'}
                    80{$portName = 'HTTP'}
                    5228{$portName = 'Google Service'}
                    25{$portName = 'SMTP'}
                    20{$portName = 'FTP'}
                    22{$portName = 'SSH'}
                }
            
                #Build connection object
                $props = @{'UserAccount'=$env:USERNAME;
                           'ComputerName'=$TCPconnection.ComputerName;
                           'localAddress'=$TCPconnection.localAddress;
                           'localPort'=$TCPconnection.localPort;
                           'RemoteAddress'=$TCPconnection.RemoteAddress;
                           'RemotePort'=$TCPconnection.RemotePort;
                           'RemotePortName'=$portName;
                           'State'=$TCPconnection.State;
                           'OwningProcessID'=$TCPconnection.OwningProcess;
                           'OwningProcess'=$OwningProcess.ProcessName;
                           'OwningProcessPath'=$OwningProcess.path;
                           'CreationTime'=$TCPconnection.CreationTime;
                           'ConnectionAge'=$TCPconnection.ConnectionAge;
                        }
            
                $obj = New-Object -TypeName PSObject -Property $props
                
                #Attempt to resolve IP to host name
                if ($IPresolve) {
                    Try {
                        $IPresolver = [System.Net.Dns]::GetHostEntry($TCPconnection.RemoteAddress)
                    } Catch {
                        Write-Warning "No such host is known for $($TCPconnection.RemoteAddress)"
                        }
                    
                    #if the IP is resolved then add the property
                    if ($IPresolver) {
                        $obj | Add-Member -MemberType NoteProperty -Name 'RemoteHostName' -Value $IPresolver.HostName
                    }
                }

                Write-Output $obj
            }
        }
    }
    End{}
}

'localhost' | Get-NetTCPConnectionIPv4 -IPresolve
