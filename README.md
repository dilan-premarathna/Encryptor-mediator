# Encryptor-mediator

Provide the key path and the content to encrypt as follows

         <property name="publicKeyPath" value="conf:/repository/pgp_public_key.asc"/>
         <property expression="$body" name="secret"/>
         <class name="org.wso2.carbon.mediator.encrypt.GPGEncrypt"/>
