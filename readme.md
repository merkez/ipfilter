# IPFilter

IPTables through Golang. It uses `iptables` command to execute rules which are defined as functions under [./iptables/iptables.go](./iptables/iptables.go).

__Currently available IP table rules are :__

- DropTraffic for all protocols or only TCP:  [DropTraffic](./iptables/iptables.go#64) function.

    - Implements following command: 
      ```bash 
      $ iptables -A INPUT -i eth0 -s "$IP_TO_BE_BLOCKED" -j DROP  // or 
      $ iptables -A INPUT -i eth0 -p tcp -s "$IP_TO_BE_BLOCKED" -j DROP
      ```

- Remove DropTraffic rule from IP tables: [RemoveDropTraffic](./iptables/iptables.go#81) function.
  
    - Implements following command:
    
    ```bash 
    $ iptables -D INPUT -i eth0 -s "$IP_TO_BE_BLOCKED" -j DROP  // or 
    $ iptables -D INPUT -i eth0 -p tcp -s "$IP_TO_BE_BLOCKED" -j DROP
    ```


## Example Run 

Here is a short video to demonstrate how it works: 

[![Watch the video](https://img.youtube.com/vi/3ZMNBwhEQIw/maxresdefault.jpg)](https://youtu.be/3ZMNBwhEQIw)





