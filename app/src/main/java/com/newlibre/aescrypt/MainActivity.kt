package com.newlibre.aescrypt

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import java.lang.Exception
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


class MainActivity : AppCompatActivity() {

    lateinit var encryptButton : Button
    lateinit var decryptButton : Button
    lateinit var passwordText : EditText
    lateinit var clearText : EditText

    lateinit var mainText : TextView;
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        encryptButton = findViewById(R.id.encryptButton)
        mainText = findViewById(R.id.mainText)
        passwordText = findViewById(R.id.passwordText)
        clearText = findViewById(R.id.clearText)
        encryptButton.setOnClickListener {
            mainText.setText(encryptData(clearText.text.toString().toByteArray(),
                passwordText.text.toString()))
        }
        decryptButton = findViewById(R.id.decryptButton)
        decryptButton.setOnClickListener {
            mainText.setText(R.string.app_name)
        }



    }

    fun encryptData(plainText : ByteArray, password: String) : String{

        val keygen = KeyGenerator.getInstance("AES")
        keygen.init(256)
        val key : SecretKey = keygen.generateKey()

        // when you convert any string to a Sha256 it will always be 32 bytes (256 bits)
        // which is exactly the size we need our AES key to be.
        val rawSha256OfPassword = ConvertStringToSha256(password);
        var keyAndIV= BytesToHex(ConvertStringToSha256(password))

        //val spec1 = SecretKeySpec(keyAndIV.substring(0..31).toByteArray(StandardCharsets.UTF_8), "AES")
        val spec1 = SecretKeySpec(rawSha256OfPassword, "AES")

        // Toast.makeText(applicationContext,key.toString(),Toast.LENGTH_LONG).show()
        //val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")//"AES/CBC/PKCS5PADDING")
        //cipher.init(Cipher.ENCRYPT_MODE, key2)

//        val ciphertext: ByteArray = cipher.doFinal(plaintext)
//        val key3: SecretKey = keygen.generateKey()

        // myIV is ALWAYS 16 bytes!!
        val myIV : ByteArray = rawSha256OfPassword.slice(0..15).toByteArray()//keyAndIV.substring(0..15).toByteArray(StandardCharsets.UTF_8)
        val newCipherText : ByteArray = encrypt(plainText,myIV,spec1)

        return newCipherText.toBase64()
    }

    fun ByteArray.toBase64(): String =
        String(Base64.getEncoder().encode(this))

    @Throws(Exception::class)
    fun encrypt(
        plaintext: ByteArray,
        IV: ByteArray,
        inSpec: SecretKeySpec
    ): ByteArray {
        //Get Cipher Instance
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

        //Create SecretKeySpec
//       var keySpec = SecretKeySpec(key.encoded, "AES")
//        keySpec = inSpec


        //Create IvParameterSpec
        val ivSpec = IvParameterSpec(IV)

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, inSpec, ivSpec)

        //Perform Encryption
        return cipher.doFinal(plaintext)
    }

    fun ConvertStringToSha256(plainText : String) : ByteArray{
        val digest: MessageDigest = MessageDigest.getInstance("SHA-256")
        val hash: ByteArray = digest.digest(plainText.toByteArray(StandardCharsets.UTF_8))
        return hash;
    }

    fun BytesToHex(sha256HashKey : ByteArray) : String{
        var hex : String = ""
        for (i in sha256HashKey) {
            // Note: The capital X in the format string causes
            // the hex value to contain uppercase hex values (A-F)
            hex += String.format("%02X", i)
        }
        return hex;
    }
}