package com.newlibre.aescrypt

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
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
            mainText.setText(crypton.encryptData(clearText.text.toString().toByteArray(),
                passwordText.text.toString()))
        }
        crypton = Crypton()
        decryptButton = findViewById(R.id.decryptButton)
        decryptButton.setOnClickListener {
            val cipherBytes = Base64.getDecoder().decode(mainText.text.toString())
            //Toast.makeText(applicationContext, mainText.text.toString(),Toast.LENGTH_LONG).show()
            //Toast.makeText(applicationContext, cipherBytes.size.toString(),Toast.LENGTH_LONG).show()
            mainText.setText(crypton.decryptData(cipherBytes,passwordText.text.toString()))
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