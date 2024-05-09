# CryptoNet

CryptoNet is a secure and simple-to-use encrypted networking framework
and login system for ComputerCraft computers. Here's an example:

##### Client:
```lua
local cryptoNet = require("cryptoNet")
-- cryptoNet.setLoggingEnabled(false)

-- Runs when the event loop starts
function onStart()
  -- Connect to the server
  local socket = cryptoNet.connect("DemoServer")
  -- Send an encrypted message
  cryptoNet.send(socket, "Hello server!")
end

-- Runs every time an event occurs
function onEvent(event)
  -- Received a message from the server
  if event[1] == "encrypted_message" then
    print("Server said: "..event[2])
  end
end

-- Let CryptoNet handle messages in the background
cryptoNet.startEventLoop(onStart, onEvent)
```

##### Server:
```lua
local cryptoNet = require("cryptoNet")
-- cryptoNet.setLoggingEnabled(false)

-- Runs when the event loop starts
function onStart()
  -- Start the server
  cryptoNet.host("DemoServer")
end

-- Runs every time an event occurs
function onEvent(event)
  -- When a client opens a connection
  if event[1] == "connection_opened" then
    -- The socket used to send messages to the client
    local socket = event[2]
    -- Send some encypted messages back to the client
    cryptoNet.send(socket, "Welcome to the server!")
    cryptoNet.send(socket, "Please wait while I show off CryptoNet...")
    -- Each call to onEvent is run in a different thread, so you can use
    -- blocking calls like sleep() and pullEvent() without freezing the whole server
    os.sleep(5)
    cryptoNet.send(socket, "Done!")
  -- Received a message from the client
  elseif event[1] == "encrypted_message" then
    print("Client says: "..event[2])
  -- Even works with non-CryptoNet events!
  elseif event[1] == "redstone" then
    print("Something redstoney happened!")
  end
end

-- Let CryptoNet handle messages in the background
cryptoNet.startEventLoop(onStart, onEvent)
```

### Login System

Here's how you use the login system:

##### Client:
```lua
local cryptoNet = require("cryptoNet")
-- cryptoNet.setLoggingEnabled(false)

function onStart()
  -- Connect to the server
  local socket = cryptoNet.connect("LoginDemoServer")
  -- Log in with a username and password
  cryptoNet.login(socket, "Bobby", "mypass123")
end

function onEvent(event)
  -- Logged in successfully
  if event[1] == "login" then
    -- The username logged in
    local username = event[2]
    -- The socket that was logged in
    local socket = event[3]
    print("Logged in as "..username)
    cryptoNet.send(socket, "Hello server!")
  -- Login failed (wrong username or password)
  elseif event[1] == "login_failed" then
    print("Didn't manage to log in. :(")
  elseif event[1] == "encrypted_message" then
    print("Server said: "..event[2])
  end
end

cryptoNet.startEventLoop(onStart, onEvent)
```

##### Server:
```lua
local cryptoNet = require("cryptoNet")
-- cryptoNet.setLoggingEnabled(false)

function onStart()
  -- Start the server
  cryptoNet.host("LoginDemoServer")
end

function onEvent(event)
  -- When a client logs in
  if event[1] == "login" then
    local username = event[2]
    -- The socket of the client that just logged in
    local socket = event[3]
    -- The logged-in username is also stored in the socket
    print(socket.username.." just logged in.")
  -- Received a message from the client
  elseif event[1] == "encrypted_message" then
    local socket = event[3]
    -- Check the username to see if the client is logged in
    if socket.username ~= nil then
      print(socket.username.." says: "..event[2])
    else
      cryptoNet.send(socket, "Sorry, I only talk to logged in users.")
    end
  end
end

cryptoNet.startEventLoop(onStart, onEvent)
```

##### Adding users to the server:
```lua
-- This can just be run in the interactive Lua prompt
local cryptoNet = require("cryptoNet")
-- Start the server to add users to
cryptoNet.host("LoginDemoServer")
-- Add a user with a password
cryptoNet.addUser("Bobby", "mypass123")
-- Close the server once we are done with it
cryptoNet.closeAll()
```

CryptoNet hashes passwords before sending them across the network, and before storing them.
This makes CryptoNet's login system much more secure than your average password door!

For an example of a secure password door made with CryptoNet, see the [door example](doorExample.md).

**Note: While CryptoNet aims to be much more secure than standard Rednet,
I am not a security expert and cannot guarantee its effectiveness. 
Do not use passwords used with other real life services with CryptoNet.**

## How CryptoNet works (and why you shouldn't use Rednet)
TL;DR Rednet has no way to prevent attackers from reading your messages,
or pretending to be another user. For more information about how CryptoNet works internally
and why it exists, check out [How CryptoNet Works](https://github.com/SiliconSloth/CryptoNet/wiki/How-CryptoNet-Works).

## Documentation
- [Clients and Servers](https://github.com/SiliconSloth/CryptoNet/wiki/Clients-and-Servers)
- [Messages and Events](https://github.com/SiliconSloth/CryptoNet/wiki/Messages-and-Events)
- [Login System](https://github.com/SiliconSloth/CryptoNet/wiki/Login-System)
- [Certificate Signing](https://github.com/SiliconSloth/CryptoNet/wiki/Certificate-Signing)
- [Settings](https://github.com/SiliconSloth/CryptoNet/wiki/Settings)

## Acknowledgements
The original project by [SiliconSloth](https://github.com/SiliconSloth) can be found [here](https://github.com/SiliconSloth/CryptoNet)

CryptoNet contains several third-party libraries that allow it to function.
Thanks to the creators of all these libraries for making CryptoNet possible!
- [SHA-256, HMAC and PBKDF2 functions in ComputerCraft by Anavrins](https://pastebin.com/6UV4qfNF)
- [Simple RSA Library by 1lann](https://gist.github.com/1lann/6604c8d3d8e5fdad0832)
- [RSA Key Generator by 1lann](https://gist.github.com/1lann/c9d4d2e7c1f825cad36b)
- [Mersenne Twister RNG and ISAAC algorithm by KillaVanilla](http://www.computercraft.info/forums2/index.php?/topic/12163-cryptographically-secure-random-number-generator/)
- [AES implementation by KillaVanilla](http://www.computercraft.info/forums2/index.php?/topic/18930-aes-encryption/)
- [Simple thread API by immibis](http://www.computercraft.info/forums2/index.php?/topic/3479-basic-background-thread-api/)
