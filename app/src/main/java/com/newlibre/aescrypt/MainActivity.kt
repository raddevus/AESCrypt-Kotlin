package com.newlibre.aescrypt

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import java.lang.Exception
import java.util.*

class MainActivity : AppCompatActivity() {

    lateinit var encryptButton : Button
    lateinit var decryptButton : Button
    lateinit var passwordText : EditText
    lateinit var clearText : EditText
    lateinit var crypton : Crypton

    lateinit var mainText : TextView;
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        encryptButton = findViewById(R.id.encryptButton)
        mainText = findViewById(R.id.mainText)
        passwordText = findViewById(R.id.passwordText)
        clearText = findViewById(R.id.clearText)
        encryptButton.setOnClickListener {
            if (passwordText.text.toString().isEmpty()){
                Toast.makeText(applicationContext, "Please add a password & try again.",Toast.LENGTH_LONG).show()
            }
            else {
                crypton = Crypton(passwordText.text.toString(),
                    clearText.text.toString().toByteArray())
                mainText.setText(
                    // call with true or blank -- true is default value
                    crypton.processData()
                )
            }
        }

        decryptButton = findViewById(R.id.decryptButton)
        decryptButton.setOnClickListener {
            if (passwordText.text.toString().isEmpty()){
                Toast.makeText(applicationContext, "Please add a password & try again.",Toast.LENGTH_LONG).show()
            }
            else {
                try {
                    val cipherBytes = Base64.getDecoder().decode(mainText.text.toString())
                    crypton = Crypton(passwordText.text.toString(),
                            cipherBytes)
                    mainText.setText(crypton.processData(false))
                } catch (ex: Exception) {
                    Toast.makeText(
                        applicationContext,
                        "Could not decode (from Base64) the cipher bytes.",
                        Toast.LENGTH_LONG)
                        .show()
                }
            }
            //Toast.makeText(applicationContext, mainText.text.toString(),Toast.LENGTH_LONG).show()
            //Toast.makeText(applicationContext, cipherBytes.size.toString(),Toast.LENGTH_LONG).show()

        }
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