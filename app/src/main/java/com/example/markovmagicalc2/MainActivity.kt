package com.example.markovmagicalc2
import android.os.Bundle
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.graphics.BitmapFactory
import android.os.Environment
import android.provider.MediaStore
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.SecretKeySpec
import android.widget.ImageView
import android.Manifest
import android.content.pm.PackageManager
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import android.net.Uri
import java.io.InputStream
import android.util.Log
import java.io.ByteArrayOutputStream
import androidx.documentfile.provider.DocumentFile
import android.provider.OpenableColumns
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.util.AttributeSet
import android.view.MotionEvent
import android.widget.LinearLayout
import javax.crypto.SecretKey
import android.util.Base64
import android.content.SharedPreferences
import java.io.BufferedReader
import java.io.InputStreamReader

object GlobalVariables {
    var idpass: Long = 1
}
class DisplayActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Встановлюємо макет для цієї активності
        setContentView(R.layout.menu4)

        // Отримуємо посилання на кнопку для переходу до екрану з паролями та додаємо обробник події
        val passButton: Button = findViewById(R.id.buttonpass)

        // Отримуємо посилання на кнопки для переходу до екранів файлів та текстів та додаємо обробники подій
        val fileButton: Button = findViewById(R.id.buttonfile)
        val textButton: Button = findViewById(R.id.buttontext)
        val dataButton: Button = findViewById(R.id.buttondata)
        val setButton: Button = findViewById(R.id.buttonsettings)
        val infoButton: Button = findViewById(R.id.buttoninfo)
        passButton.setOnClickListener { viewPass() }
        fileButton.setOnClickListener { viewImfile() }
        textButton.setOnClickListener { viewText() }
        dataButton.setOnClickListener { viewDataButton() }
        setButton.setOnClickListener  { viewSettings() }
       // infoButton.setOnClickListener { viewInfo() }
    }

    private fun viewSettings(){
        val intent = Intent(this, ChangeCodeActivity::class.java)
        startActivity(intent)
    }
    private fun viewInfo(){
        val intent = Intent(this, InfoActivity::class.java)
        startActivity(intent)
    }
    // Метод для переходу до екрану з паролями
    private fun viewPass() {
        val intent = Intent(this, PasswordActivity::class.java)
        startActivity(intent)
    }

    // Метод для переходу до екрану з текстами
    private fun viewText() {
        val intent = Intent(this, TextActivity::class.java)
        startActivity(intent)
    }
    private fun viewDataButton() {
        val intent = Intent(this, FileActivity::class.java)
        startActivity(intent)
    }
    // Метод для переходу до екрану з файлами
    private fun viewImfile() {
        val intent = Intent(this, ImfaileActivity::class.java)
        startActivity(intent)
    }
}

class Calculator : AppCompatActivity() {

    private lateinit var inputTextView: TextView
    private var isNumericLast: Boolean = false
    private var isDotLast: Boolean = false
    private var isErrorState: Boolean = false
    private var entercode = "9999"
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val sharedPreferences: SharedPreferences = getSharedPreferences("MyPrefs", Context.MODE_PRIVATE)
        entercode = sharedPreferences.getString("enter_code", "9999") ?: "9999"
        inputTextView = findViewById(R.id.inputTextView)
    }

    fun onDigitClick(view: View) {
        if (isErrorState) {
            inputTextView.text = (view as Button).text
            isErrorState = false
        } else {
            inputTextView.append((view as Button).text)
        }
        isNumericLast = true
        isDotLast = false
    }

    fun onDecimalClick(view: View) {
        if (isNumericLast && !isDotLast) {
            inputTextView.append(".")
            isNumericLast = false
            isDotLast = true
        }
    }

    fun onClearClick(view: View) {
        inputTextView.text = ""
        isNumericLast = false
        isDotLast = false
        isErrorState = false
    }

    fun onBackspaceClick(view: View) {
        val text = inputTextView.text.toString()
        if (text.isNotEmpty()) {
            inputTextView.text = text.substring(0, text.length - 1)
        }
        isNumericLast = inputTextView.text.isNotEmpty() && inputTextView.text.last().isDigit()
        isDotLast = inputTextView.text.endsWith(".")
    }

    fun onOperatorClick(view: View) {
        if (isNumericLast && !isOperatorAdded(inputTextView.text.toString())) {
            inputTextView.append((view as Button).text)
            isNumericLast = false
            isDotLast = false
        }
    }

    private fun viewLocker() {
        val intent = Intent(this, viewLock::class.java)
        startActivity(intent)
    }

    fun onEqualClick(view: View) {
        if (isNumericLast) {
            var inputValue = inputTextView.text.toString()
            var prefix = ""
            if (inputValue == entercode) {
                viewLocker()
                return
            }
            try {
                if (inputValue.startsWith("-")) {
                    prefix = "-"
                    inputValue = inputValue.substring(1)
                }

                if (inputValue.contains("-")) {
                    val splitValue = inputValue.split("-")
                    var one = splitValue[0]
                    val two = splitValue[1]

                    if (prefix.isNotEmpty()) {
                        one = prefix + one
                    }

                    inputTextView.text = removeTrailingZero((one.toDouble() - two.toDouble()).toString())
                } else if (inputValue.contains("+")) {
                    val splitValue = inputValue.split("+")
                    var one = splitValue[0]
                    val two = splitValue[1]

                    if (prefix.isNotEmpty()) {
                        one = prefix + one
                    }

                    inputTextView.text = removeTrailingZero((one.toDouble() + two.toDouble()).toString())
                } else if (inputValue.contains("*")) {
                    val splitValue = inputValue.split("*")
                    var one = splitValue[0]
                    val two = splitValue[1]

                    if (prefix.isNotEmpty()) {
                        one = prefix + one
                    }

                    inputTextView.text = removeTrailingZero((one.toDouble() * two.toDouble()).toString())
                } else if (inputValue.contains("/")) {
                    val splitValue = inputValue.split("/")
                    var one = splitValue[0]
                    val two = splitValue[1]

                    if (prefix.isNotEmpty()) {
                        one = prefix + one
                    }

                    if (two.toDouble() != 0.0) {
                        inputTextView.text = removeTrailingZero((one.toDouble() / two.toDouble()).toString())
                    } else {
                        inputTextView.text = "Error"
                        isErrorState = true
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
                isErrorState = true
                inputTextView.text = "Error"
            }
        }
    }

    private fun isOperatorAdded(value: String): Boolean {
        // Если строка начинается с "-" и это не единственный символ, проверяем дальше
        if (value.startsWith("-") && value.length > 1) {
            val subValue = value.substring(1)
            return subValue.contains("/") || subValue.contains("*") || subValue.contains("-") || subValue.contains("+")
        }
        return value.contains("/") || value.contains("*") || value.contains("-") || value.contains("+")
    }

    private fun removeTrailingZero(result: String): String {
        var value = result
        if (result.contains(".0")) {
            value = result.substring(0, result.length - 2)
        }
        return value
    }
}
class PasswordActivity : AppCompatActivity() {
    private lateinit var passwordTextView: TextView
    private lateinit var passwordLengthEditText: EditText
    private lateinit var uppercaseSwitch: Switch
    private lateinit var lowercaseSwitch: Switch
    private lateinit var digitsSwitch: Switch
    private lateinit var symbolsSwitch: Switch
    private lateinit var generateButton: Button
    private lateinit var copyButton: Button
    private lateinit var saveButton: Button
    private lateinit var viewDatabaseButton: Button
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.a_pass)
        passwordTextView = findViewById(R.id.passwordTextView)
        passwordLengthEditText = findViewById(R.id.passwordLengthEditText)
        uppercaseSwitch = findViewById(R.id.uppercaseSwitch)
        lowercaseSwitch = findViewById(R.id.lowercaseSwitch)
        digitsSwitch = findViewById(R.id.digitsSwitch)
        symbolsSwitch = findViewById(R.id.symbolsSwitch)
        generateButton = findViewById(R.id.generateButton)
        copyButton = findViewById(R.id.copyButton)
        saveButton = findViewById(R.id.saveButton)
        viewDatabaseButton = findViewById(R.id.viewDatabaseButton)
        generateButton.setOnClickListener { generatePassword() }
        copyButton.setOnClickListener { copyToClipboard() }
        saveButton.setOnClickListener { savePassword() }
        viewDatabaseButton.setOnClickListener { viewDatabase() }
    }
    private fun generatePassword() {
        try {
            val passwordLength = passwordLengthEditText.text.toString().toIntOrNull() ?: 8
            val includeUppercase = uppercaseSwitch.isChecked
            val includeLowercase = lowercaseSwitch.isChecked
            val includeDigits = digitsSwitch.isChecked
            val includeSymbols = symbolsSwitch.isChecked
            val generatedPassword = PasswordGenerator.generateStrongPassword(
                passwordLength,
                includeUppercase,
                includeLowercase,
                includeDigits,
                includeSymbols
            )
            passwordTextView.text = "$generatedPassword"
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
    private fun viewDatabase() {
        val intent = Intent(this, DisplayDataActivity::class.java)
        startActivity(intent)
    }
    private fun savePassword() {
        val generatedPassword = passwordTextView.text.toString()
        if (generatedPassword.isNotEmpty()) {
            val intent = Intent(this, SaveActivity::class.java)
            intent.putExtra("generatedPassword", generatedPassword)
            startActivity(intent)
        } else {
            Toast.makeText(this, "No password to save", Toast.LENGTH_SHORT).show()
        }
    }
    /*
    private fun generateStrongPassword(
        length: Int,
        includeUppercase: Boolean,
        includeLowercase: Boolean,
        includeDigits: Boolean,
        includeSymbols: Boolean
    ): String {
        val password = StringBuilder()
        val uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        val lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
        val digitChars = "0123456789"
        val symbolChars = "!*()_+-=[]{}|;:,.<>?"
        if (includeUppercase) password.append(uppercaseChars.random())
        if (includeLowercase) password.append(lowercaseChars.random())
        if (includeDigits) password.append(digitChars.random())
        if (includeSymbols) password.append(symbolChars.random())
        val remainingLength = length - password.length
        val allChars = buildString {
            if (includeUppercase) append(uppercaseChars)
            if (includeLowercase) append(lowercaseChars)
            if (includeDigits) append(digitChars)
            if (includeSymbols) append(symbolChars)
        }
        password.append((1..remainingLength).map { allChars.random() }.joinToString(""))
        password.replace(1, password.length - 1, password.substring(1).toList().shuffled().joinToString(""))
        return password.toString()
    }

     */
    private fun copyToClipboard() {
        val generatedPassword = passwordTextView.text.toString()
        if (generatedPassword.isNotEmpty()) {
            val clipboardManager =
                getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Password", generatedPassword)
            clipboardManager.setPrimaryClip(clip)
            Toast.makeText(this, "скопійовано в буфер обміну", Toast.LENGTH_SHORT).show()
        }
    }
}
object PasswordGenerator {
    fun generateStrongPassword(
        length: Int,
        includeUppercase: Boolean,
        includeLowercase: Boolean,
        includeDigits: Boolean,
        includeSymbols: Boolean
    ): String {
        val password = StringBuilder()
        val uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        val lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
        val digitChars = "0123456789"
        val symbolChars = "!*()_+-=[]{}|;:,.<>?"
        if (includeUppercase) password.append(uppercaseChars.random())
        if (includeLowercase) password.append(lowercaseChars.random())
        if (includeDigits) password.append(digitChars.random())
        if (includeSymbols) password.append(symbolChars.random())
        val remainingLength = length - password.length
        val allChars = buildString {
            if (includeUppercase) append(uppercaseChars)
            if (includeLowercase) append(lowercaseChars)
            if (includeDigits) append(digitChars)
            if (includeSymbols) append(symbolChars)
        }
        password.append((1..remainingLength).map { allChars.random() }.joinToString(""))
        password.replace(1, password.length - 1, password.substring(1).toList().shuffled().joinToString(""))
        return password.toString()
    }
    fun getKeyAES128(): String{
        val CryptoKey = generateStrongPassword(15, true, true, true, false)
        return CryptoKey
    }
}
class DatabaseHelper(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    override fun onCreate(db: SQLiteDatabase) {
        // Создаем первую таблицу
        val createPasswordTableQuery = """
            CREATE TABLE $PASSWORD_TABLE_NAME (
                $PASSWORD_COLUMN_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                $PASSWORD_COLUMN_SERVICE TEXT,
                $PASSWORD_COLUMN_LOGIN TEXT,
                $PASSWORD_COLUMN_PASSWORD TEXT,
                $PASSWORD_COLUMN_DATE_TIME TEXT
            )
        """.trimIndent()
        db.execSQL(createPasswordTableQuery)

        // Создаем новую таблицу
        val createCryptoKeyTableQuery = """
            CREATE TABLE $CRYPTO_KEY_TABLE_NAME (
                $CRYPTO_KEY_COLUMN_ID INTEGER PRIMARY KEY,
                $CRYPTO_KEY_COLUMN_STRING TEXT
            )
        """.trimIndent()
        db.execSQL(createCryptoKeyTableQuery)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $PASSWORD_TABLE_NAME")
        db.execSQL("DROP TABLE IF EXISTS $CRYPTO_KEY_TABLE_NAME")
        onCreate(db)
    }

    // Методы для работы с таблицей паролей
    fun getAllData(): List<DataModel> {
        val dataList = mutableListOf<DataModel>()
        val db = readableDatabase
        val cursor = db.rawQuery("SELECT * FROM $PASSWORD_TABLE_NAME", null)
        val serviceIndex = cursor.getColumnIndex(PASSWORD_COLUMN_SERVICE)
        val loginIndex = cursor.getColumnIndex(PASSWORD_COLUMN_LOGIN)
        val passwordIndex = cursor.getColumnIndex(PASSWORD_COLUMN_PASSWORD)
        val dateTimeIndex = cursor.getColumnIndex(PASSWORD_COLUMN_DATE_TIME)
        while (cursor.moveToNext()) {
            val service = if (serviceIndex != -1) cursor.getString(serviceIndex) else ""
            val login = if (loginIndex != -1) cursor.getString(loginIndex) else ""
            val password = if (passwordIndex != -1) cursor.getString(passwordIndex) else ""
            val dateTime = if (dateTimeIndex != -1) cursor.getString(dateTimeIndex) else ""
            val dataModel = DataModel(service, login, password, dateTime)
            dataList.add(dataModel)
        }
        cursor.close()
        db.close()
        return dataList
    }

    // Методы для работы с таблицей криптографических ключей
    fun getStringById(id: Long): String? {
        val db = this.readableDatabase
        val cursor = db.query(
            CRYPTO_KEY_TABLE_NAME, arrayOf(CRYPTO_KEY_COLUMN_STRING), "$CRYPTO_KEY_COLUMN_ID = ?", arrayOf(id.toString()),
            null, null, null
        )

        return if (cursor.moveToFirst()) {
            val result = cursor.getString(cursor.getColumnIndexOrThrow(CRYPTO_KEY_COLUMN_STRING))
            cursor.close()
            result
        } else {
            cursor.close()
            null
        }
    }

    fun insertString(id: Long, string: String) {
        val db = this.writableDatabase
        val contentValues = ContentValues().apply {
            put(CRYPTO_KEY_COLUMN_ID, id)
            put(CRYPTO_KEY_COLUMN_STRING, string)
        }
        db.insert(CRYPTO_KEY_TABLE_NAME, null, contentValues)
    }
    // Новый метод для получения строки или вставки строки по умолчанию
    fun getStringOrInsertDefault(id: Long): String {
        val existingCryptoKey = getStringById(id)
        return if (existingCryptoKey != null) {
            existingCryptoKey
        } else {
            val newCryptoKey = PasswordGenerator.getKeyAES128()
            insertString(id, newCryptoKey)
            newCryptoKey
        }
    }


    companion object {
        const val DATABASE_NAME = "passwords.db"
        const val DATABASE_VERSION = 2 // Обновляем версию базы данных

        // Константы для таблицы паролей
        const val PASSWORD_TABLE_NAME = "passwords"
        const val PASSWORD_COLUMN_ID = "id"
        const val PASSWORD_COLUMN_SERVICE = "service"
        const val PASSWORD_COLUMN_LOGIN = "login"
        const val PASSWORD_COLUMN_PASSWORD = "password"
        const val PASSWORD_COLUMN_DATE_TIME = "date_time"

        // Константы для таблицы криптографических ключей
        const val CRYPTO_KEY_TABLE_NAME = "crypto_keys"
        const val CRYPTO_KEY_COLUMN_ID = "id"
        const val CRYPTO_KEY_COLUMN_STRING = "string"
    }
}
data class DataModel(
    val service: String,
    val login: String,
    val password: String,
    val dateTime: String
)
class DataAdapter(private val dataList: List<DataModel>, private val onItemClick: (String) -> Unit): RecyclerView.Adapter<DataAdapter.ViewHolder>() {
    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val serviceTextView: TextView = itemView.findViewById(R.id.textViewService)
        val loginTextView: TextView = itemView.findViewById(R.id.textViewLogin)
        val passwordTextView: TextView = itemView.findViewById(R.id.textViewPassword)
        val dateTimeTextView: TextView = itemView.findViewById(R.id.textViewDateTime)
    }
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_row, parent, false)
        return ViewHolder(view)
    }
    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val data = dataList[position]
        holder.serviceTextView.text = "Service: ${data.service}"
        holder.loginTextView.text = "Login: ${data.login}"
        holder.passwordTextView.text = "Password: ${data.password}"
        holder.dateTimeTextView.text = "Date/Time: ${data.dateTime}"
        holder.itemView.setOnClickListener {
            onItemClick.invoke(data.password) // Pass password to onItemClick listener
        }
    }
    override fun getItemCount(): Int {
        return dataList.size
    }
}
class SaveActivity : AppCompatActivity() {
    private lateinit var dbHelper: DatabaseHelper

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.save)

        dbHelper = DatabaseHelper(this)

        val generatedPassword = intent.getStringExtra("generatedPassword")
        val editTextService = findViewById<EditText>(R.id.editTextService)
        val editTextLogin = findViewById<EditText>(R.id.editTextLogin)
        val editTextPassword = findViewById<EditText>(R.id.editTextPassword)
        val buttonSave = findViewById<Button>(R.id.buttonSave)
        val buttonCancel = findViewById<Button>(R.id.buttonCancel)

        editTextPassword.setText(generatedPassword)

        buttonSave.setOnClickListener {
            val service = editTextService.text.toString()
            val login = editTextLogin.text.toString()
            val password = editTextPassword.text.toString()
            saveToDatabase(service, login, password)
        }

        buttonCancel.setOnClickListener { returnToMainActivity() }
    }

    private fun saveToDatabase(service: String, login: String, password: String) {
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put(DatabaseHelper.PASSWORD_COLUMN_SERVICE, service)
            put(DatabaseHelper.PASSWORD_COLUMN_LOGIN, login)
            put(DatabaseHelper.PASSWORD_COLUMN_PASSWORD, password)
            put(DatabaseHelper.PASSWORD_COLUMN_DATE_TIME, getCurrentDateTime())
        }
        db.insert(DatabaseHelper.PASSWORD_TABLE_NAME, null, values)
        db.close()

        returnToMainActivity()
    }

    private fun getCurrentDateTime(): String {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        val date = Date()
        return dateFormat.format(date)
    }

    private fun returnToMainActivity() {
        dbHelper.close()
        finish()
    }
}
class DisplayDataActivity : AppCompatActivity() {
    private lateinit var recyclerView: RecyclerView
    private lateinit var adapter: DataAdapter
    private lateinit var dbHelper: DatabaseHelper

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_display_data)
        recyclerView = findViewById(R.id.recyclerView)
        dbHelper = DatabaseHelper(this)
        adapter = DataAdapter(dbHelper.getAllData()) {
                password ->

            copyPasswordToClipboard(password)
        }
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter
    }

    override fun onDestroy() {
        super.onDestroy()
        dbHelper.close()
    }

    private fun copyPasswordToClipboard(password: String) {
        val clipboardManager =
            getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("Password", password)
        clipboardManager.setPrimaryClip(clip)

        Toast.makeText(this, "скопійовано в буфер обміну", Toast.LENGTH_SHORT).show()
    }
}
class TextActivity : AppCompatActivity() {

    private lateinit var editText: EditText
    private lateinit var keyEditText: EditText
    private lateinit var encryptButton: Button
    private lateinit var decryptButton: Button
    private lateinit var copyButton: Button
    private lateinit var pasteButton: Button
    private lateinit var copyKeyButton: Button
    private lateinit var generateKeyButton: Button
    private lateinit var clipboardManager: ClipboardManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_text2)

        editText = findViewById(R.id.editText)
        keyEditText = findViewById(R.id.keyEditText)
        encryptButton = findViewById(R.id.encryptButton)
        decryptButton = findViewById(R.id.decryptButton)
        copyButton = findViewById(R.id.copyButton)
        pasteButton = findViewById(R.id.pasteButton)
        copyKeyButton = findViewById(R.id.copyKeyButton)
        generateKeyButton = findViewById(R.id.generateKeyButton)
        clipboardManager = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

        // Generate initial key
        val initialKey = generateKey()
        keyEditText.setText(initialKey)

        encryptButton.setOnClickListener {
            val inputText = editText.text.toString()
            val secretKey = getKeyFromText()
            if (secretKey != null) {
                val encryptedText = AESHelper.encrypt(inputText, secretKey)
                editText.setText(encryptedText)
            } else {
                Toast.makeText(this, "Invalid key", Toast.LENGTH_SHORT).show()
            }
        }

        decryptButton.setOnClickListener {
            val inputText = editText.text.toString()
            val secretKey = getKeyFromText()
            if (secretKey != null) {
                val decryptedText = AESHelper.decrypt(inputText, secretKey)
                editText.setText(decryptedText)
            } else {
                Toast.makeText(this, "Invalid key", Toast.LENGTH_SHORT).show()
            }
        }

        copyButton.setOnClickListener {
            copyToClipboard(editText.text.toString())
        }

        pasteButton.setOnClickListener {
            pasteFromClipboard()
        }

        copyKeyButton.setOnClickListener {
            copyToClipboard(keyEditText.text.toString())
        }

        generateKeyButton.setOnClickListener {
            val newKey = generateKey()
            keyEditText.setText(newKey)
        }
    }

    private fun copyToClipboard(data: String) {
        if (data.isNotEmpty()) {
            val temp = ClipData.newPlainText("text", data)
            clipboardManager.setPrimaryClip(temp)
            Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show()
        }
    }

    private fun pasteFromClipboard() {
        val clipData = clipboardManager.primaryClip
        if (clipData != null && clipData.itemCount > 0) {
            val pasteData = clipData.getItemAt(0).text.toString()
            editText.setText(pasteData)
        }
    }


    fun stringToSecretKey(keyString: String): SecretKey {
        val keyBytes = keyString.toByteArray(Charsets.UTF_8)  // Преобразуем строку в байтовый массив
        return SecretKeySpec(keyBytes, "AES")  // Создаем SecretKeySpec с указанием алгоритма
    }
    fun convertAndCompareKeys(inputString: String) {
        // Преобразование строки в SecretKey
        val secretKey = SecretKeySpec(Base64.decode(inputString, Base64.DEFAULT), "AES")

        // Преобразование SecretKey обратно в строку
        val outputString =  Base64.encodeToString(secretKey.encoded, Base64.DEFAULT)

        // Формирование сообщения для Toast
        val message = "String1: $inputString\nString2: $outputString"

        // Вывод Toast
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }


    private fun generateKey(): String{
        val keyGen = PasswordGenerator.getKeyAES128()
        return keyGen
    }

    private fun getKeyFromText(): SecretKey? {
        return try {
            val key = keyEditText.text.toString().toByteArray(Charsets.UTF_8)
            SecretKeySpec(key, 0, key.size, "AES")
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}
object AESHelper {

    private const val ALGORITHM = "AES"

    fun encrypt(data: String, secretKey: SecretKey): String {
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedBytes = cipher.doFinal(data.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    fun decrypt(data: String, secretKey: SecretKey): String {
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        val decryptedBytes = cipher.doFinal(Base64.decode(data, Base64.DEFAULT))
        return String(decryptedBytes)
    }
}
class ImfaileActivity : AppCompatActivity() {
    private val REQUEST_PERMISSION_CODE = 123
    private val ENCRYPT_REQUEST_CODE = 1
    private val DECRYPT_REQUEST_CODE = 2
    private lateinit var key: String // Объявляем переменную без инициализации
    private lateinit var imageView: ImageView
    private lateinit var encryptButton: Button
    private lateinit var decryptButton: Button
    private var picPath: String = ""
    private lateinit var fileEncryptionManager: FileEncryptionManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.imfile_crypt)
        encryptButton = findViewById(R.id.idBtnEncrypt)
        decryptButton = findViewById(R.id.idBtnDecrypt)
        imageView = findViewById(R.id.idivimage)

        key = DatabaseHelper(this).getStringOrInsertDefault(GlobalVariables.idpass) // Use password as the id// Ensure the key is 16/24/32 bytes for AES// 16 символов = 128 бит
        fileEncryptionManager = FileEncryptionManager(key)
        checkPermissions()

        encryptButton.setOnClickListener {
            val intent = Intent(Intent.ACTION_PICK, android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI)
            startActivityForResult(intent, ENCRYPT_REQUEST_CODE)
        }

        decryptButton.setOnClickListener {
            val intent = Intent(Intent.ACTION_PICK, android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI)
            startActivityForResult(intent, DECRYPT_REQUEST_CODE)
        }
    }

    private fun checkPermissions() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE), REQUEST_PERMISSION_CODE)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_PERMISSION_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                // Permissions granted, do nothing
            } else {
                Toast.makeText(this, "Разрешения на доступ к файлам не были предоставлены.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == RESULT_OK && data != null) {
            val imgUri = data.data
            val filePathColumn = arrayOf(MediaStore.Images.Media.DATA)
            val cursor = contentResolver.query(imgUri!!, filePathColumn, null, null, null)
            cursor?.use {
                if (it.moveToFirst()) {
                    val columnIndex = it.getColumnIndex(filePathColumn[0])
                    picPath = it.getString(columnIndex)
                }
            }

            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED) {
                when (requestCode) {
                    ENCRYPT_REQUEST_CODE -> fileEncryptionManager.encryptFile(picPath)
                    DECRYPT_REQUEST_CODE -> {
                        if (fileEncryptionManager.decryptFile(picPath)) {
                            displayDecryptedImage(picPath)
                        } else {
                            Toast.makeText(this, "Не удалось расшифровать изображение.", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            } else {
                checkPermissions()
            }
        }
    }

    private fun displayDecryptedImage(path: String) {
        val file = File(path)
        if (file.exists()) {
            val bitmap = BitmapFactory.decodeFile(file.path)
            imageView.setImageBitmap(bitmap)
        } else {
            Log.e("ImfaileActivity", "Файл не существует для отображения")
        }
    }

    private fun getFilePath(fileName: String): String {
        val contextWrapper = ContextWrapper(applicationContext)
        val myDirectory = contextWrapper.getExternalFilesDir(Environment.DIRECTORY_PICTURES)
        return File(myDirectory, fileName).path
    }
}
class FileActivity : AppCompatActivity() {
    private lateinit var encryptionKey: String // Объявляем переменную без инициализации
    private val TAG = "FileActivity"
    private val PICK_FILE_REQUEST_CODE_ENCRYPT = 1
    private val PICK_FILE_REQUEST_CODE_DECRYPT = 2
    private lateinit var fileEncryptionManager: FileEncryptionManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_datacrypt)

        encryptionKey = DatabaseHelper(this).getStringOrInsertDefault(GlobalVariables.idpass) // Use password as the id// Ensure the key is 16/24/32 bytes for AES
        Toast.makeText(this, "Пароль: $encryptionKey ", Toast.LENGTH_SHORT).show()
        fileEncryptionManager = FileEncryptionManager(encryptionKey)

        // Check permissions
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE), 1)
        }

        val encryptButton: Button = findViewById(R.id.idencrypt2)
        val decryptButton: Button = findViewById(R.id.iddecrypt2)

        encryptButton.setOnClickListener {
            pickFileForAction(PICK_FILE_REQUEST_CODE_ENCRYPT)
        }

        decryptButton.setOnClickListener {
            pickFileForAction(PICK_FILE_REQUEST_CODE_DECRYPT)
        }
    }

    private fun pickFileForAction(requestCode: Int) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            type = "*/*" // Allow selection of any file
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        startActivityForResult(intent, requestCode)
    }

    //@Deprecated
    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (resultCode == RESULT_OK && data != null) {
            val uri: Uri? = data.data
            uri?.let {
                when (requestCode) {
                    PICK_FILE_REQUEST_CODE_ENCRYPT -> {
                        handleFile(uri, Cipher.ENCRYPT_MODE)
                    }
                    PICK_FILE_REQUEST_CODE_DECRYPT -> {
                        handleFile(uri, Cipher.DECRYPT_MODE)
                    }
                }
            }
        }
    }

    private fun handleFile(uri: Uri, mode: Int) {
        try {
            val byteArrayOutputStream = ByteArrayOutputStream()

            contentResolver.openInputStream(uri)?.use { inputStream ->
                if (mode == Cipher.ENCRYPT_MODE) {
                    fileEncryptionManager.encryptStream(inputStream, byteArrayOutputStream)
                } else {
                    fileEncryptionManager.decryptStream(inputStream, byteArrayOutputStream)
                }
            }

            val byteArray = byteArrayOutputStream.toByteArray()
            saveFileInSameDirectory(uri, byteArray)

            val message = if (mode == Cipher.ENCRYPT_MODE) "File encrypted and replaced successfully" else "File decrypted and replaced successfully"
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            Log.d(TAG, message)

        } catch (ex: Exception) {
            Log.e(TAG, "Error processing file", ex)
        }
    }

    private fun getFileNameFromUri(uri: Uri): String {
        var fileName = "output_file"
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            cursor.moveToFirst()
            fileName = cursor.getString(nameIndex)
        }
        return fileName
    }

    private fun saveFileInSameDirectory(originalUri: Uri, byteArray: ByteArray) {
        try {
            val documentFile = DocumentFile.fromSingleUri(this, originalUri)
            documentFile?.uri?.let { uri ->
                contentResolver.openOutputStream(uri)?.use { outputStream ->
                    outputStream.write(byteArray)
                    outputStream.flush()
                }
            }
        } catch (ex: Exception) {
            Log.e(TAG, "Error saving file", ex)
        }
    }
}
class FileEncryptionManager(private val key: String) {

    companion object {
        private const val ALGORITHM = "AES"
        private const val TRANSFORMATION = "AES"
    }

    fun encryptFile(path: String) {
        val file = File(path)
        if (!file.exists()) {
            Log.e("FileEncryptionManager", "Файл не существует")
            return
        }

        try {
            val tempFile = File(file.parent, "tempfile.enc")
            FileInputStream(file).use { fis ->
                FileOutputStream(tempFile).use { fos ->
                    val sks = SecretKeySpec(key.toByteArray(), ALGORITHM)
                    val cipher = Cipher.getInstance(TRANSFORMATION)
                    cipher.init(Cipher.ENCRYPT_MODE, sks)
                    CipherOutputStream(fos, cipher).use { cos ->
                        val buffer = ByteArray(1024)
                        var bytesRead: Int
                        while (fis.read(buffer).also { bytesRead = it } != -1) {
                            cos.write(buffer, 0, bytesRead)
                        }
                    }
                }
            }
            if (file.delete()) {
                tempFile.renameTo(file)
                Log.d("FileEncryptionManager", "Файл успешно зашифрован.")
            } else {
                Log.e("FileEncryptionManager", "Не удалось удалить исходный файл")
            }
        } catch (e: Exception) {
            Log.e("FileEncryptionManager", "Ошибка при шифровании файла: ${e.message}")
        }
    }

    fun decryptFile(path: String): Boolean {
        val file = File(path)
        val tempFile = File(file.parent, "tempfile.dec")

        if (!file.exists()) {
            Log.e("FileEncryptionManager", "Файл для расшифровки не существует")
            return false
        }

        return try {
            FileInputStream(file).use { fis ->
                FileOutputStream(tempFile).use { fos ->
                    val sks = SecretKeySpec(key.toByteArray(), ALGORITHM)
                    val cipher = Cipher.getInstance(TRANSFORMATION)
                    cipher.init(Cipher.DECRYPT_MODE, sks)
                    CipherInputStream(fis, cipher).use { cis ->
                        val buffer = ByteArray(1024)
                        var bytesRead: Int
                        while (cis.read(buffer).also { bytesRead = it } != -1) {
                            fos.write(buffer, 0, bytesRead)
                        }
                    }
                }
            }
            if (file.delete()) {
                tempFile.renameTo(file)
                Log.d("FileEncryptionManager", "Файл успешно расшифрован.")
                true
            } else {
                Log.e("FileEncryptionManager", "Не удалось удалить зашифрованный файл")
                false
            }
        } catch (e: Exception) {
            Log.e("FileEncryptionManager", "Ошибка при расшифровке файла: ${e.message}")
            false
        }
    }

    fun encryptStream(inputStream: InputStream, outputStream: ByteArrayOutputStream) {
        doCrypto(Cipher.ENCRYPT_MODE, inputStream, outputStream)
    }

    fun decryptStream(inputStream: InputStream, outputStream: ByteArrayOutputStream) {
        doCrypto(Cipher.DECRYPT_MODE, inputStream, outputStream)
    }

    private fun doCrypto(cipherMode: Int, inputStream: InputStream, outputStream: ByteArrayOutputStream) {
        try {
            val secretKey = SecretKeySpec(key.toByteArray(), ALGORITHM)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(cipherMode, secretKey)

            if (cipherMode == Cipher.ENCRYPT_MODE) {
                CipherOutputStream(outputStream, cipher).use { cipherOutputStream ->
                    val buffer = ByteArray(1024)
                    var bytesRead: Int
                    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                        cipherOutputStream.write(buffer, 0, bytesRead)
                    }
                }
            } else {
                CipherInputStream(inputStream, cipher).use { cipherInputStream ->
                    val buffer = ByteArray(1024)
                    var bytesRead: Int
                    while (cipherInputStream.read(buffer).also { bytesRead = it } != -1) {
                        outputStream.write(buffer, 0, bytesRead)
                    }
                }
            }
        } catch (ex: Exception) {
            throw RuntimeException("Ошибка при шифровании/дешифровании файла", ex)
        }
    }
}
interface OnPasswordCompleteListener {
    fun onPasswordComplete(password: Long)
}
class viewLock : AppCompatActivity(), OnPasswordCompleteListener {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_lock)

        // Add PatternLockView to the layout
        val patternLockView = PatternLockView(this)
        patternLockView.setOnPasswordCompleteListener(this) // Set the listener
        findViewById<LinearLayout>(R.id.patternLockContainer).addView(patternLockView)
    }

    override fun onPasswordComplete(password: Long) {
        // Display the password in a Toast
        Toast.makeText(this, "Пароль: ${password.toString()}", Toast.LENGTH_SHORT).show()
        GlobalVariables.idpass = password
        // Use 'this' as the context to create DatabaseHelper
        val dbHelper = DatabaseHelper(this)
        val usedCryptoKey = dbHelper.getStringOrInsertDefault(password) // Use password as the id
        println("Resulting string: $usedCryptoKey")
        Toast.makeText(this, "Пароль: ${dbHelper.getStringOrInsertDefault(password)}", Toast.LENGTH_SHORT).show()

        // Call viewMenu after displaying the toast
        viewMenu()
    }

    private fun viewMenu() {
        val intent = Intent(this, DisplayActivity::class.java)
        startActivity(intent)
    }
}
class PatternLockView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    // Paint settings for drawing circles
    private val circlePaint = Paint().apply {
        color = Color.BLACK
        style = Paint.Style.FILL
        isAntiAlias = true
    }

    // Paint settings for drawing lines
    private val linePaint = Paint().apply {
        color = Color.BLACK
        style = Paint.Style.STROKE
        strokeWidth = 5f
        isAntiAlias = true
    }

    private val circles = ArrayList<Triple<Float, Float, Int>>() // List to store circle coordinates and indices
    private val touchedCircles = HashSet<Int>() // Set to store indices of touched circles
    private val lines = ArrayList<Pair<Pair<Float, Float>, Pair<Float, Float>>>() // List to store line coordinates between circles
    private var currentX = 0f // Current X coordinate for drawing line
    private var currentY = 0f // Current Y coordinate for drawing line
    private var password = StringBuilder() // Variable to store the password
    private var currentTouchedCircleIndex: Int? = null // Index of touched circle
    private var passwordCompleteListener: OnPasswordCompleteListener? = null

    // Method called when the size of the view changes
    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        val padding = 100
        val space = (w - 2 * padding) / 2
        val verticalOffset = (h - w) / 2

        // Initialize circle coordinates
        circles.clear()
        var index = 1
        for (i in 0..2) {
            for (j in 0..2) {
                // Add the coordinates of each circle to the list
                circles.add(Triple((i * space + padding).toFloat(), (j * space + padding + verticalOffset).toFloat(), index))
                index++
            }
        }
    }

    // Method to draw the view
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        // Draw circles
        for (circle in circles) {
            // Change the color of the circle if it is touched
            circlePaint.color = if (circle.third == currentTouchedCircleIndex) Color.RED else Color.BLACK
            canvas.drawCircle(circle.first, circle.second, 50f, circlePaint)
        }

        // Draw lines between circles
        for (line in lines) {
            canvas.drawLine(line.first.first, line.first.second, line.second.first, line.second.second, linePaint)
        }

        // Draw the current line from the last circle to the current finger position
        if (lines.isNotEmpty()) {
            val lastCircle = lines.last().second
            canvas.drawLine(lastCircle.first, lastCircle.second, currentX, currentY, linePaint)
        }
    }

    // Method to handle touch events
    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.action) {
            MotionEvent.ACTION_DOWN, MotionEvent.ACTION_MOVE -> {
                // Update current coordinates
                currentX = event.x
                currentY = event.y

                // Check if we touched a circle
                val touchedCircle = getTouchedCircle(currentX, currentY)
                if (touchedCircle != null) {
                    // Find the index of the touched circle
                    val circleIndex = circles.find { it.first == touchedCircle.first && it.second == touchedCircle.second }?.third
                    if (circleIndex != null && circleIndex != currentTouchedCircleIndex) {
                        currentTouchedCircleIndex = circleIndex
                        // Add a new line if it hasn't been added yet
                        if (lines.isEmpty() || lines.last().second != touchedCircle) {
                            if (lines.isNotEmpty()) {
                                lines.add(Pair(lines.last().second, touchedCircle))
                            } else {
                                lines.add(Pair(touchedCircle, touchedCircle))
                            }
                            // Add the circle index to the password
                            password.append(circleIndex)
                            // Add the circle index to the set of touched circles
                            touchedCircles.add(circleIndex)
                        }
                    }
                }
                invalidate() // Refresh the view
            }
            MotionEvent.ACTION_UP -> {
                // Handle password input completion
                val passwordId = password.toString().toLong()
                passwordCompleteListener?.onPasswordComplete(passwordId)
                password.clear() // Clear the password after completion
                lines.clear() // Clear the lines after completion
                touchedCircles.clear() // Clear the set of touched circles after completion
                currentTouchedCircleIndex = null // Clear the index of the touched circle after completion
                invalidate() // Refresh the view
            }
        }
        return true
    }

    // Method to check if we touched any circle
    private fun getTouchedCircle(x: Float, y: Float): Pair<Float, Float>? {
        for (circle in circles) {
            // Check if the touch coordinates are inside the circle
            if (Math.hypot((circle.first - x).toDouble(), (circle.second - y).toDouble()) < 50) {
                return Pair(circle.first, circle.second)
            }
        }
        return null
    }

    fun setOnPasswordCompleteListener(listener: OnPasswordCompleteListener) {
        this.passwordCompleteListener = listener
    }
}
class ChangeCodeActivity : AppCompatActivity() {
    private lateinit var enterCodeEditText: EditText
    private lateinit var saveButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.a_set)

        enterCodeEditText = findViewById(R.id.enter_code_edit_text)
        saveButton = findViewById(R.id.save_button)

        // Load the current enter_code from SharedPreferences
        val sharedPreferences: SharedPreferences = getSharedPreferences("MyPrefs", Context.MODE_PRIVATE)
        val currentCode = sharedPreferences.getString("enter_code", "9999")
        enterCodeEditText.setText(currentCode)

        saveButton.setOnClickListener {
            val newCode = enterCodeEditText.text.toString()
            if (newCode.isNotEmpty()) {
                // Save the new enter_code to SharedPreferences
                with(sharedPreferences.edit()) {
                    putString("enter_code", newCode)
                    apply()
                }
                Toast.makeText(this, "Code saved successfully", Toast.LENGTH_SHORT).show()
                finish() // Close the activity
            } else {
                Toast.makeText(this, "Please enter a valid code", Toast.LENGTH_SHORT).show()
            }
        }
    }
}


class InfoActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.a_info)

        val textView: TextView = findViewById(R.id.text_view1)
        val largeText = loadTextFromAsset("readme.txt")

        textView.text = largeText
    }

    private fun loadTextFromAsset(fileName: String): String {
        val stringBuilder = StringBuilder()
        try {
            val reader = BufferedReader(InputStreamReader(assets.open(fileName)))
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                stringBuilder.append(line).append('\n')
            }
            reader.close()
        } catch (e: Exception) {
            Log.e("InfoActivity", "Error reading asset file", e)
        }
        return stringBuilder.toString()
    }
}
