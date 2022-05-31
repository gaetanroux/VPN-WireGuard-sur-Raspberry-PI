# Mise en place d'un VPN WireGuard sur Raspberry PI


## Shéma

![](https://i.imgur.com/C4VyCT5.png)

## Installation et configuration du serveur WireGuard

- Mise à jour du cache des paquets et installation de wireguard 

```
sudo apt-get update
```

```
sudo apt-get install wireguard
```

## Mettre en place une interface WireGuard

- Nous allons créer la clé privée **/etc/wireguard/wg-private.key** et la clé publique **/etc/wireguard/wg-public.key** grâce à cet enchaînement de 
commandes :

```
wg genkey | sudo tee /etc/wireguard/wg-private.key | wg pubkey | sudo tee /etc/wireguard/wg-public.key
```

- La valeur de la clé publique sera retournée dans la console. Au sein du fichier de configuration de WireGuard, nous devons **ajouter la valeur de notre clé privée**. Pour récupérer cette valeur, saisissez la commande ci-dessous et copiez la valeur :

```
sudo cat /etc/wireguard/wg-private.key
```

- Il est temps de créer un fichier de configuration dans **/etc/wireguard/**. Par exemple, nous pouvons nommer ce fichier **wg0.conf**, si l'on estime que l'interface réseau associée à WireGuard sera **wg0**.

```
sudo nano /etc/wireguard/wg0.conf
```

- Dans ce fichier, nous devons ajouter le contenu suivant dans un premier temps (nous reviendrons le compléter par la suite) :

```
[Interface]
Address = 192.168.110.121/24
SaveConfig = true
ListenPort = 51820
PrivateKey = <clé privée du serveur>
```

- La section **[Interface]** sert à déclarer la partie serveur. Voici quelques informations :

    **Address** : l'adresse IP de l'interface WireGuard au sein du tunnel VPN (sous-réseau différent du LAN distant)
    **SaveConfig** : la configuration est mise en mémoire (et protégée) tout le temps que l'interface est active
    **ListenPort** : le port d'écoute de WireGuard, ici c'est **51820** qui est le port par défaut, mais je vous invite à le personnaliser
    **PrivateKey** : la valeur de la clé privée de notre serveur (**wg-private.key**)


- Sauvegardez le fichier et fermez-le. Avec la commande "wg-quick", nous pouvons démarrer cette interface en précisant son nom (wg0, car le fichier se nomme wg0.conf) :


```
sudo wg-quick up wg0
```

- Si vous listez les adresses IP de votre serveur Raspberry PI, vous allez voir une nouvelle interface nommée **wg0** avec l'adresse IP définie dans le fichier de config :

```
ip a
```

```
ynov@raspberrypi:~ $ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether b8:27:eb:3e:4f:a9 brd ff:ff:ff:ff:ff:ff
    inet 169.254.0.18/16 brd 169.254.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet 192.168.1.18/24 brd 192.168.1.255 scope global noprefixroute eth0
       valid_lft forever preferred_lft forever
    inet6 2a01:cb19:9a8:3d00:9901:5969:ed9a:88f4/64 scope global dynamic mngtmpaddr noprefixroute
       valid_lft 86390sec preferred_lft 590sec
    inet6 fe80::571b:142b:2605:32cc/64 scope link
       valid_lft forever preferred_lft forever
    inet6 fe80::ba27:ebff:fe3e:4fa9/64 scope link
       valid_lft forever preferred_lft forever
6: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN group default qlen 1000
    link/none
    inet 192.168.110.18/24 scope global wg0
       valid_lft forever preferred_lft forever
```

- Dans le même esprit, nous pouvons afficher la configuration de l'interface **wg0** via la commande **wg show** : 



```
sudo wg show wg0
```

```
ynov@raspberrypi:~ $ sudo wg show wg0
interface: wg0
  public key: dSKp7yPN99BpFEiszTZjRDTkx5nwiP1XFawC8/Rb4gA=
  private key: (hidden)
  listening port: 51820

peer: l68uu2pAsB+v/vTH+ktRtDYxvOOwFVqSv0Ro7btQfgw=
  endpoint: **.***.**.**:49817
  allowed ips: 192.168.110.23/32
  latest handshake: 2 days, 6 hours, 15 minutes, 34 seconds ago
  transfer: 237.69 KiB received, 692.86 KiB sent

peer: /cVq0WxU0tDc6gzmrVBiUwPz86UIBSWi+0jh7i3hRyU=
  endpoint: **.***.**.**:59053
  allowed ips: 192.168.110.21/32
  latest handshake: 2 days, 6 hours, 18 minutes, 21 seconds ago
  transfer: 116.19 KiB received, 164.68 KiB sent
```

- Enfin, il reste à activer le démarrage automatique de notre interface wg0 WireGuard :


```
sudo systemctl enable wg-quick@wg0.service
```

## Activer l'IP Forwarding

- Pour que notre machine Debian 11 soit en mesure de router les paquets entre les différents réseaux (tel un routeur), c'est-à-dire entre le réseau du VPN et le réseau local, nous devons activer l'IP Forwarding. Par défaut, cette fonctionnalité est désactivée.

- Modifiez ce fichier de configuration :


```
sudo nano /etc/sysctl.conf
```

- Ajoutez la directive suivante à la fin du fichier et enregistrez :


```
net.ipv4.ip_forward = 1
```

## Activer l'IP Masquerade

- Pour que notre serveur puisse router correctement les paquets et que le LAN distant soit accessible à la machine Windows, il faut activer l'IP Masquerade sur notre serveur Debian. C'est en quelque sorte l'activation du NAT. Je vais effectuer cette configuration sur le pare-feu Linux au travers d'UFW.

- Si vous n'avez pas encore UFW et que vous souhaitez le mettre en place (vous pouvez aussi passer par Nftables), commencer par l'installer : 


```
sudo apt install ufw
```


- Tout d'abord, il faut autoriser le SSH pour ne pas perdre la main sur le serveur distant (adaptez le numéro de port) :

```
sudo ufw allow 22/tcp
```

- Le port 51820 en UDP doit aussi être autorisé, car nous l'utilisons pour WireGuard (là encore, adaptez le numéro de port) :

```
sudo ufw allow 51820/udp
```

- Ensuite, on va poursuivre la configuration afin d'activer l'IP masquerade. Pour cela, il faut récupérer le nom de l'interface qui est connectée au réseau local. Si vous ne connaissez pas le nom, exécutez **ip a** afin de voir le nom de la carte. Dans mon cas, on peut voir que c'est la carte **eth0**.

```
ynov@raspberrypi:~ $ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: **eth0**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether b8:27:eb:3e:4f:a9 brd ff:ff:ff:ff:ff:ff
    inet 169.254.0.18/16 brd 169.254.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet 192.168.1.18/24 brd 192.168.1.255 scope global noprefixroute eth0
       valid_lft forever preferred_lft forever
    inet6 2a01:cb19:9a8:3d00:9901:5969:ed9a:88f4/64 scope global dynamic mngtmpaddr noprefixroute
       valid_lft 86359sec preferred_lft 559sec
    inet6 fe80::571b:142b:2605:32cc/64 scope link
       valid_lft forever preferred_lft forever
    inet6 fe80::ba27:ebff:fe3e:4fa9/64 scope link
       valid_lft forever preferred_lft forever
6: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN group default qlen 1000
    link/none
    inet 192.168.110.18/24 scope global wg0
```


- On va se servir de cette information. Éditez le fichier suivant :

```
sudo nano /etc/ufw/before.rules
```

- Ajoutez ces lignes à la fin du fichier afin **d'activer l'IP masquerade sur l'interface eth0** (adaptez le nom de l'interface) au sein de la chaîne POSTROUTING de la table NAT de notre pare-feu local :

```
# NAT - IP masquerade
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o ens192 -j MASQUERADE

# End each table with the 'COMMIT' line or these rules won't be processed
COMMIT
```

Gardez ce fichier de configuration ouvert et passez à l'étape suivante. 😉

## Configuration du pare-feu Linux pour WireGuard

- Toujours au sein du même fichier de configuration, on va déclarer le réseau d'entreprise "192.168.1.0/24" afin que l'on puisse le contacter. Voici les deux règles à ajouter (idéalement après la section "# ok icmp code for FORWARD" pour regrouper les règles) :

```# autoriser le forwarding pour le réseau distant de confiance (+ le réseau du VPN)
-A ufw-before-forward -s 192.168.1.0/24 -j ACCEPT
-A ufw-before-forward -d 192.168.1.0/24 -j ACCEPT
-A ufw-before-forward -s 192.168.110.0/24 -j ACCEPT
-A ufw-before-forward -d 192.168.110.0/24 -j ACCEPT
```

- Désormais, vous pouvez sauvegarder le fichier puis le fermer. Il ne reste plus qu'à activer UFW et à redémarrer le service pour appliquer nos changements :

```
sudo ufw enable
```
```
sudo systemctl restart ufw
```

## Client WireGuard sous Windows

- Après avoir téléchargé l'exécutable ou le package MSI de WireGuard, l'installation est simple puisqu'il suffit de lancer l'installeur, et puis...voilà, c'est fait ! 🙂

- Commencez par ouvrir le logiciel afin de créer un nouveau tunnel, pour cela cliquez sur la flèche à droite du bouton "Ajouter le tunnel" et cliquez sur le bouton "Ajouter un tunnel vide".

![](https://i.imgur.com/yD0hfqA.png)

- Une fenêtre de configuration va s'ouvrir. À chaque fois que l'on crée une nouvelle configuration de tunnel, WireGuard génère un couple de clés privé/public propre à cette configuration. **Dans cette configuration, nous devons déclarer le "peer", c'est-à-dire le serveur distant**. Pour le moment, nous avons seulement ceci :

```
[Interface]
PrivateKey = <la clé privée du PC>
```
![](https://i.imgur.com/siYGl3J.png)

- Nous devons compléter cette configuration, notamment pour déclarer l'adresse IP sur cette interface (Address), mais aussi pour déclarer le serveur WireGuard distant via un bloc **[Peer]**. L'image ci-dessous doit vous rappeler le fichier de configuration que l'on a créé du côté du serveur Linux.

- Commençons par le bloc **[Interface]** en ajoutant l'adresse IP **"192.168.110.20"** ; je vous rappelle que le serveur dispose de l'adresse IP **"192.168.110.18"** sur ce segment réseau. Ce qui donne :

```
[Interface]
PrivateKey = <la clé privée du PC>
Address = 192.168.110.20/24
```
![](https://i.imgur.com/qD8gRsn.png)

- Ensuite, nous devons déclarer le bloc **[Peer]** avec trois propriétés, ce qui donne cette configuration :

```
[Peer]
PublicKey = <PublicKey-serveur-Raspberry>
AllowedIPs = 192.168.110.0/24, 192.168.100.0/24
Endpoint = <ip-public-serveur-Raspberry>:51820
```

- Pour connaitre votre **ip-public-serveur** faite **curl ifconfig.me**

![](https://i.imgur.com/VK86ErP.png)

- Quelques explications au sujet du bloc [Peer] :

    **PublicKey** : il s'agit de la clé publique du serveur WireGuard Debian 11 (vous pouvez obtenir sa valeur via la commande "sudo wg")
    **AllowedIPs** : il s'agit des adresses IP / des sous-réseaux accessibles via ce réseau VPN WireGuard, ici il s'agit du sous-réseau propre à mon VPN WireGuard (192.168.110.0/24) et de mon LAN distant (192.168.1.0/24)
    **Endpoint** : il s'agit de l'adresse IP de l'hôte Raspberry PI puisque c'est notre point de liaison WireGuard (il faudra préciser l'adresse IP publique)

- Pour finir, donnez un nom en renseignant le champ **"Nom"** (sans espaces) et copiez-collez la clé publique du client, car nous allons devoir la déclarer sur le serveur. Cliquez sur **"Enregistrer"**.

## Déclarer le client sur le serveur WireGuard

- Il est temps de retourner sur le serveur Debian dans le but de déclarer le **[Peer]** c'est-à-dire notre PC Windows dans la configuration de WireGuard. Tout d'abord, il faut **stopper l'interface "wg0"** afin de pouvoir modifier sa configuration :

```
sudo wg-quick down wg0
# ou
sudo wg-quick down /etc/wireguard/wg0.conf
```
- Ensuite, modifiez le fichier de configuration précédemment créé :

```
sudo nano /etc/wireguard/wg0.conf
```

- Dans ce fichier, à la suite du bloc **[Interface]**, il faut que l'on déclare un bloc **[Peer]** :

```
[Peer]
PublicKey = MXi3IlDqQNLSGqiMva++RNSVntpM4i3PUngj1fC30Bs=
AllowedIPs = 192.168.110.20/32
```

- Ce bloc **[Peer]** contient la clé publique du PC Windows 10 (PublicKey) ainsi que l'adresse IP de l'interface de ce PC (AllowedIPs) : le serveur communiquera dans ce tunnel WireGuard uniquement pour contacter le client Windows, d'où la valeur **"192.168.110.20/32"**.

- Il ne reste plus qu'à sauvegarder le fichier (CTRL+O puis Entrée puis CTRL+X via Nano). Relancez l'interface **"wg0"** :

```
sudo wg-quick up wg0
# ou
sudo wg-quick up /etc/wireguard/wg0.conf
```

- Pour vérifier que la déclaration du **[peer]** fonctionne, vous pouvez utiliser cette commande :

```
sudo wg show
```

- À partir du moment où l'hôte distant aura monté sa connexion WireGuard, son adresse IP va remonter au sein de la valeur **"Endpoint"**.

```
ynov@raspberrypi:~ $ sudo wg show
interface: wg0
  public key: dSKp7yPN99BpFEiszTZjRDTkx5nwiP1XFawC8/Rb4gA=
  private key: (hidden)
  listening port: 51820

peer: MXi3IlDqQNLSGqiMva++RNSVntpM4i3PUngj1fC30Bs=
  endpoint: **.***.**.**:60278
  allowed ips: 192.168.110.20/32
  latest handshake: 48 seconds ago
  transfer: 42.80 KiB received, 39.04 KiB sent

peer: l68uu2pAsB+v/vTH+ktRtDYxvOOwFVqSv0Ro7btQfgw=
  endpoint: **.***.**.**:49817
  allowed ips: 192.168.110.23/32
  latest handshake: 2 days, 6 hours, 52 minutes, 39 seconds ago
  transfer: 237.69 KiB received, 692.86 KiB sent

peer: /cVq0WxU0tDc6gzmrVBiUwPz86UIBSWi+0jh7i3hRyU=
  endpoint: **.***.**.**:59053
  allowed ips: 192.168.110.21/32
  latest handshake: 2 days, 6 hours, 55 minutes, 26 seconds ago
  transfer: 116.19 KiB received, 164.68 KiB sent
```
 - Pour finir, on va sécuriser les fichiers de configuration pour limiter l'accès à "root" :

```
sudo chmod 600 /etc/wireguard/ -R
```


## Première connexion avec WireGuard

- La configuration est prête, nous pouvons l'initier depuis le PC Windows. Pour cela, au sein du client "WireGuard", cliquez sur le bouton "Activer" : la connexion va passer de "Eteinte" à "Activée", mais cela ne veut pas dire que ça fonctionnera. Tout dépend si toute votre configuration est correcte ou non. Lorsque la connexion est établie, nos deux machines communiquent via l'interface WireGuard configurée de chaque côté !
![](https://i.imgur.com/iU1JUQc.png)

- À partir de mon PC distant, je peux pinguer l'adresse IP de mon interface WireGuard côté serveur, ainsi qu'un hôte de mon LAN distant.

```
PS C:\Users\gaeta> ping 192.168.110.18

Envoi d’une requête 'Ping'  192.168.110.18 avec 32 octets de données :
Réponse de 192.168.110.18 : octets=32 temps=77 ms TTL=64
Réponse de 192.168.110.18 : octets=32 temps=251 ms TTL=64
Réponse de 192.168.110.18 : octets=32 temps=306 ms TTL=64
Réponse de 192.168.110.18 : octets=32 temps=38 ms TTL=64
```

**Voilà, votre VPN WireGuard est en place et il est opérationnel ! Félicitations !** 🙂



## Bonus Monitoring

- Installer la clé publique de RPi-Monitor pour certifier le dépôt :

```
sudo apt-get install dirmngr
sudo apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 2C0D3C0F
```

- Exécutez les commandes suivantes pour ajouter RPi-Monitor à la liste de vos dépôts :

```
Exécutez les commandes suivantes pour ajouter RPi-Monitor à la liste de vos dépôts
```

- Vous pouvez maintenant installer RPi-Monitor: 

```
sudo apt-get update
sudo apt-get install rpimonitor
```

- Pour accéder à l'interface web de monitoring :

```
ip-raspberry:8888
```

- !! Ne pas oublié d'ouvrir ce port via le firewall !!

```
sudo ufw allow 22/tcp
```
```
sudo systemctl restart ufw
```

**Vous avez maintenant un service de monitoring !**


