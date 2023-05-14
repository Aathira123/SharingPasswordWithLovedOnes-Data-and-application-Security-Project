import io
import tempfile
from urllib.parse import urlparse
import struct
import flask
import shamirs


#from apiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import googleapiclient.discovery
from requests import HTTPError
from google_auth import build_credentials, get_user_info

from werkzeug.utils import secure_filename


#for encryption
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import scrypt
import google_auth
import os
import gdown

app = flask.Blueprint('google_drive', __name__)


def build_drive_api_v3():
    credentials = build_credentials()
    return googleapiclient.discovery.build('drive', 'v3', credentials=credentials).files()


def build_drive_service_v3():
    credentials = build_credentials()
    return googleapiclient.discovery.build('drive', 'v3', credentials=credentials)

def set_permission(file_id):
    service = build_drive_service_v3()
    try:
        permission = {'type': 'anyone',
                      'value': 'anyone',
                      'role': 'reader'}
        return service.permissions().create(fileId=file_id,body=permission).execute()
    except HTTPError as error:
        return print('Error while setting permission:', error)

def save_image(file_name, mime_type, file_data,file_id=None):
    drive_api = build_drive_api_v3()

    generate_ids_result = drive_api.generateIds(count=1).execute()
    new_file_id = generate_ids_result['ids'][0]

   

    if not file_id:
        body = {
            'id': new_file_id,
            'name': file_name,
            'mimeType': mime_type,
            "role": "reader",
            "type": "anyone",
            'value': '',

        }
    else:
        body = {
            'name': file_name,
            'mimeType': mime_type,
            "role": "reader",
            "type": "anyone",
            'value': '',

        }

    media_body = MediaIoBaseUpload(file_data,
                                   mimetype=mime_type,
                                   resumable=True)
    
    if not file_id:
        drive_api.create(body=body,
                         media_body=media_body,
                         fields='id,name,mimeType,createdTime,modifiedTime').execute()
        file_id = new_file_id

    else:
        drive_api.update(fileId =file_id,body=body,
                         media_body=media_body,
                         fields='id,name,mimeType,createdTime,modifiedTime').execute()
    set_permission(file_id)

    return file_id

@app.route('/googleDrive/share/<file_id>', methods=['GET', 'POST'])

def share_file_with_shamir(file_id):
    drive_api = build_drive_api_v3()

    metadata = drive_api.get(fields="name,mimeType,webViewLink", fileId=file_id).execute()
    if flask.request.method == 'GET':
        return flask.render_template('share.html', file_content='',url=metadata['webViewLink'],
                                     user_info=google_auth.get_user_info(),file_id=file_id)
    

    return flask.redirect('/')
@app.route('/googleDrive/back/<file_id>', methods=['GET','POST'])
def back(file_id):
    
    drive_api = build_drive_api_v3()

    metadata = drive_api.get(fields="name,mimeType,webViewLink", fileId=file_id).execute()
    

    return flask.redirect('/')

@app.route('/googleDrive/view-shared-file', methods=['GET', 'POST'])
def viewSharedFile():
      # get password
    if flask.request.method == 'GET':
        return flask.render_template('viewShared.html', file_content='',user_info=google_auth.get_user_info(),
                                     view_share=True)

    s1=flask.request.form.get("share1")
    s2=flask.request.form.get("share2")
    fileUrl = flask.request.form.get("url")

    print(s1,s2,fileUrl)
    print(type(s1),type(s2),type(fileUrl))

    s1_hex=hex(int(s1, 16))
    s2_hex=hex(int(s2, 16))


    # print(hex(s1))
    a = urlparse(fileUrl)
    print(s1_hex,s2_hex,a)

    m=99999999999999999999999999999999999999999999999999999999999999999999999999999
    sh=list()
    sh1=shamirs.share(index=1,value=int(s1, 16),modulus=m)
    sh2=shamirs.share(index=2,value=int(s2, 16),modulus=m)
    sh.append(sh1)
    sh.append(sh2)
    key_got=shamirs.interpolate(sh)
    b1 = key_got.to_bytes(32, byteorder='big')

# print(shamirs.interpolate(sh))


    print(b1)

    file_out = tempfile.TemporaryFile()
    file_name = os.path.basename(a.path)
    # file = requests.get(fileUrl, allow_redirects=True)
    fileU =  "https://drive.google.com/uc?id={}".format(fileUrl.split("/")[5])
    print(fileU)
    
    download_file_from_google_drive(fileU, file_out)
 
    file_out.seek(0)
    # interpolate


    try:
        file_out,key = decrypt(file_name,'',file_out,key=b1)
        file_out.seek(0)
        # return {"response": file_out.read().decode("utf-8")}

    except ValueError as e:
        print(str(e))
        return {"response":"Error - Corrupted Data"}
    
    file_data = file_out.read()

    print(file_data.decode("utf-8").split("\n"))
    file_info=file_data.decode("utf-8").replace('\r','')
    #print(file_info)
    file_info=file_info.split('\n')
    #print(file_info)

    return flask.render_template('viewShared.html', file_content=file_data.decode("utf-8") ,user_info=google_auth.get_user_info(),
                                     view_share=True)
    # return flask.render_template('viewShared.html', file_content="" ,user_info=google_auth.get_user_info(),
    #                                  view_share=True)

@app.route('/googleDrive/upload', methods=['GET', 'POST'])
def upload_file():
    if 'file' not in flask.request.files:
        return flask.redirect('/')

    file = flask.request.files['file']
    if (not file):
        return flask.redirect('/')
    
    filename = secure_filename(file.filename)

    password = flask.request.form.get('password')
    filename = secure_filename(file.filename)
    file_out = encrypt(filename,password,file)
    file_out.seek(0)

    mime_type = flask.request.headers['Content-Type']
    save_image(filename, mime_type, file_out,file_id=None)
    

    return flask.redirect('/')



@app.route('/googleDrive/view/<file_id>', methods=['GET','POST'])
#for decryption and viewing contents of the file
def viewFile(file_id):
    # get password and tag
    if flask.request.method == 'GET':
        return flask.render_template('edit.html', file_content='',
                                     user_info=google_auth.get_user_info(),file_id=file_id)

    #post use the pass and tag specified ti mak changes to the html 
    drive_api = build_drive_api_v3()

    metadata = drive_api.get(fields="name,mimeType,webViewLink", fileId=file_id).execute()

    share_url = metadata['webViewLink']
    print(share_url)
    request = drive_api.get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)

    done = False
    while done is False:
        status, done = downloader.next_chunk()

    fh.seek(0)
    file_name = metadata['name']
    password = flask.request.form.get("password")
    tag = flask.request.form.get("tag")

    #print(password,tag)

    #display the whole file
    try:
        file_out,key = decrypt(file_name,password,fh,key=None)
        file_out.seek(0)
    except ValueError as e:
        return flask.render_template('edit.html', file_content="Unauthorized Access",
                                    user_info=google_auth.get_user_info(), file_name=file_name)
    file_data = file_out.read()
    

    print(file_data.decode("utf-8").split("\n"))
    file_info=file_data.decode("utf-8").replace('\r','')
    #print(file_info)
    file_info=file_info.split('\n')
    #print(file_info)
    
    w=[]
    for i in file_info:
        i=i[1:len(i)-1]
        words=i.split(',')
        w.append(words)

    #add the required contenet in the tag 
    print(w)

    display_content=""
    for i in w:
        if i[0]==tag:
            display_content=" ".join(i[1:])

    print(display_content)
    

    if tag=="":
       
        return  flask.render_template('edit.html', file_content=file_data.decode("utf-8") ,
                                    user_info=google_auth.get_user_info(), file_name = file_name,
                                    file_id=file_id,password = password)
    else:
        
        return  flask.render_template('edit.html', file_content=display_content ,
                                    user_info=google_auth.get_user_info(), file_name = file_name,
                                    file_id=file_id,password = password)
        


@app.route('/googleDrive/getFile/<file_id>', methods=['GET','POST'])
def getFile(file_id):
    # get password and tag
    if flask.request.method == 'GET':
        return flask.render_template('update.html', file_content='',
                                     user_info=google_auth.get_user_info(),file_id=file_id)

    #post use the pass and tag specified ti mak changes to the html 
    drive_api = build_drive_api_v3()

    metadata = drive_api.get(fields="name,mimeType,webViewLink", fileId=file_id).execute()
    share_url = metadata['webViewLink']
    print(share_url)
    request = drive_api.get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)

    done = False
    while done is False:
        status, done = downloader.next_chunk()

    fh.seek(0)
    file_name = metadata['name']
    password = flask.request.form.get("password")

    #display the whole file
    try:
        file_out,key = decrypt(file_name,password,fh,key=None)
        file_out.seek(0)
    except ValueError as e:
        return flask.render_template('update.html', file_content="Unauthorized Access",
                                    user_info=google_auth.get_user_info(), file_name=file_name)
    file_data = file_out.read()
    file_info=file_data.decode("utf-8").replace('\r','')

  
    return  flask.render_template('update.html', file_content=file_data.decode("utf-8") ,
                            user_info=google_auth.get_user_info(), file_name = file_name,
                            file_id=file_id,password = password)



@app.route('/googleDrive/update/<file_id>', methods=['GET','POST'])
def updateFile(file_id):
    
    drive_api = build_drive_api_v3()

    metadata = drive_api.get(fields="name,mimeType,webViewLink", fileId=file_id).execute()

    request = drive_api.get_media(fileId=file_id)
    
    file_name = metadata['name']
    password = flask.request.form.get("new")
    content = flask.request.form.get("content")

    print(password,content)
    file_out = tempfile.TemporaryFile()
    file_out.write(content.encode('utf-8'))
    file_out.seek(0)
    file_out = encrypt(file_name, password, file_out)
    file_out.seek(0)
    mime_type = flask.request.headers['Content-Type']
    print(file_id)
    save_image(file_name, mime_type, file_out,file_id=file_id)

    return flask.redirect('/')
    
@app.route('/googleDrive/delete/<file_id>', methods=['GET'])
def delete_file(file_id):
    drive_api = build_drive_api_v3()
    drive_api.delete(fileId=file_id).execute()

    return flask.redirect('/')

@app.route('/googleDrive/sShare/<file_id>', methods=['GET','POST'])
def share_file(file_id):
    drive_api = build_drive_api_v3()

    metadata = drive_api.get(fields="name,mimeType,webViewLink", fileId=file_id).execute()
    if flask.request.method == 'GET':
        # return flask.render_template('sShare.html', file_content='',
        #                              user_info=google_auth.get_user_info(),file_id=file_id)
        return flask.render_template('sShare.html', file_content='',url=metadata['webViewLink'],
                                     user_info=google_auth.get_user_info(),file_id=file_id)

    #post use the pass and tag specified ti mak changes to the html 
    # drive_api = build_drive_api_v3()

    # metadata = drive_api.get(fields="name,mimeType,webViewLink", fileId=file_id).execute()
    

    file_name = metadata['name']
    password = flask.request.form.get("password")
    #print(password,tag)

    #display the whole file

    n=flask.request.form.get("n")
    t=flask.request.form.get("t")
    secret=flask.request.form.get("secret")

    print(password,n,t,secret)
    

    if password!="":
        #this is to decrypt and print the sec key
        print("hey")
        request = drive_api.get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)

        done = False
        while done is False:
            status, done = downloader.next_chunk()

        fh.seek(0)
        try:
            file_out,key = decrypt(file_name,password,fh,key=None)
            # key_int=int(key, 16)
            # print(key,key_int)
            
        except ValueError as e:
            return flask.render_template('sShare.html', secret="Unauthorized Access",
                                        user_info=google_auth.get_user_info(), file_name=file_name)
        
        print(key)

       
        # num = struct.unpack('<I', key)[0]  # unpack bytes as little-endian unsigned integer
        # print(num)
        int_key32=int.from_bytes(key, byteorder='big', signed=False)

        gen_key = shamirs.shares(int_key32, quantity=3,modulus=99999999999999999999999999999999999999999999999999999999999999999999999999999)

        return  flask.render_template('sShare.html', secret=hex(int_key32) ,url=metadata['webViewLink'],
                                    user_info=google_auth.get_user_info(), file_name = file_name, share1=hex(gen_key[0].value),share2=hex(gen_key[1].value),share3=hex(gen_key[2].value),
                                    file_id=file_id,password = password)

    # else:
    #     n=flask.request.form.get("n")
    #     t=flask.request.form.get("t")
    #     key=flask.request.form.get("secret")
    #     key_int=int(key, 16)

    #     print(n,t,key,key_int)
    #     gen_shares=shamirs.share(key_int,3)
    #     print(gen_shares)
    #     return  flask.render_template('sShare.html', secret=key,
    #                                 user_info=google_auth.get_user_info(), file_name = file_name,share1="h",share2="b",share3="c",
    #                                 file_id=file_id,password = password)
        



@app.route('/googleDrive/save/<file_id>', methods=['POST'])
def update_file(file_id):


    drive_api = build_drive_api_v3()

    metadata = drive_api.get(fields="name,mimeType", fileId=file_id).execute()

    file_name = metadata['name']
    password = flask.request.form.get("password")
    content = flask.request.form.get("content")
    file_out = tempfile.TemporaryFile()
    file_out.write(content.encode('utf-8'))
    file_out.seek(0)
    file_out = encrypt(file_name, password, file_out)
    file_out.seek(0)
    mime_type = flask.request.headers['Content-Type']
    print(file_id)
    save_image(file_name, mime_type, file_out,file_id=file_id)

    return flask.redirect('/')

def download_file_from_google_drive(url, destination):
        gdown.download(url, destination, quiet=False)

        return destination

# 


def encrypt(filename,user_password,file_in):

    BUFFER_SIZE = 1024 * 1024  # The size in bytes that we read, encrypt and write to at once

    password = user_password  # Get this from somewhere else like input()

    input_filename = filename  # Any file extension will work
    # output_filename = input_filename + '.encrypted'  # You can name this anything, I'm just putting .encrypted on the end

    file_out = tempfile.TemporaryFile()

    # Open files
    #file_in = file_in  # rb = read bytes. Required to read non-text files
    #file_out = open(output_filename, 'wb')  # wb = write bytes. Required to write the encrypted data

    salt = get_random_bytes(32)  # Generate salt
    key = scrypt(password, salt, key_len=32, N=2 ** 17, r=8, p=1)  # Generate a key using the password and salt
    file_out.write(salt)  # Write the salt to the top of the output file

    cipher = AES.new(key, AES.MODE_GCM)  # Create a cipher object to encrypt data
    file_out.write(cipher.nonce)  # Write out the nonce to the output file under the salt

    # Read, encrypt and write the data
    data = file_in.read(BUFFER_SIZE)  # Read in some of the file
    while len(data) != 0:  # Check if we need to encrypt anymore data
        encrypted_data = cipher.encrypt(data)  # Encrypt the data we read
        file_out.write(encrypted_data)  # Write the encrypted data to the output file
        data = file_in.read(BUFFER_SIZE)  # Read some more of the file to see if there is any more left

    # Get and write the tag for decryption verification
    tag = cipher.digest()  # Signal to the cipher that we are done and get the tag
    file_out.write(tag)
    # print(tag, "Encrypt tag")
    # Close both files
    file_in.close()
    # file_out.close()

    return file_out

def decrypt(filename,user_password,file_in,key=None):

    BUFFER_SIZE = 1024 * 1024  # The size in bytes that we read, encrypt and write to at once
    # print(file_in.read())
    # file_in.seek(0)
    password = user_password  # Get this from somewhere else like input()

    output_filename = filename  # The decrypted file
    file_in.seek(0, os.SEEK_END)
    file_size = file_in.tell()
    file_in.seek(0)
    # Open files
    file_in = file_in
    file_out = tempfile.TemporaryFile()
    salt = file_in.read(32)  # The salt we generated was 32 bits long

    # Read salt and generate key
    if not key:
        key = scrypt(password, salt, key_len=32, N=2 ** 17, r=8, p=1)  # Generate a key using the password and salt again
    # Read nonce and create cipher
    nonce = file_in.read(16)  # The nonce is 16 bytes long
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Identify how many bytes of encrypted there is
    # We know that the salt (32) + the nonce (16) + the data (?) + the tag (16) is in the file
    # So some basic algebra can tell us how much data we need to read to decrypt
    file_in_size = file_size
    encrypted_data_size = file_in_size - 32 - 16 - 16  # Total - salt - nonce - tag = encrypted data
    # Read, decrypt and write the data
    for _ in range(
            int(encrypted_data_size / BUFFER_SIZE)):  # Identify how many loops of full buffer reads we need to do
        data = file_in.read(BUFFER_SIZE)  # Read in some data from the encrypted file
        decrypted_data = cipher.decrypt(data)  # Decrypt the data
        file_out.write(decrypted_data)  # Write the decrypted data to the output file
    data = file_in.read(
        int(encrypted_data_size % BUFFER_SIZE))  # Read whatever we have calculated to be left of encrypted data
    decrypted_data = cipher.decrypt(data)  # Decrypt the data
    file_out.write(decrypted_data)  # Write the decrypted data to the output file

    # Verify encrypted file was not tampered with
    tag = file_in.read(16)
    try:
        cipher.verify(tag)
    except ValueError as e:
        # If we get a ValueError, there was an error when decrypting so delete the file we created
        file_in.close()
        file_out.close()
        try:
            os.remove(output_filename)
        except Exception as error:
            pass

        raise e

    # If everything was ok, close the files
    file_in.close()
    # file_out.close()
    return file_out,key