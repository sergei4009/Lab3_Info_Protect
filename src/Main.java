
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import java.util.List;

public class Main extends JFrame{
    private BigInteger modulus_N, salt, generator_g, multiplier_k;
    private static BigInteger N;
    private BigInteger sIdentityHash, sVerifier, scrambler;
    BigInteger sessionKey, privateKey, publicKey;
    public static Map<String, String> saltTable = new HashMap<>();
    public static Map<String, String> verifTable = new HashMap<>();
    JTextField logArea;
    JPasswordField pasArea;
    JTextArea logi;



    public Main(){
       super("Lab Rab 4-SRP");
        LoginWindow();
    }


    public void LoginWindow() {
        setVisible(true);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        Box box1 = Box.createHorizontalBox();
        JLabel loginLabel = new JLabel("UN:");
        logArea = new JTextField(20);
        box1.add(loginLabel);
        box1.add(Box.createHorizontalStrut(8));
        box1.add(logArea);
        Box box2 = Box.createHorizontalBox();
        JLabel passwordLabel = new JLabel("Pass:");
        pasArea = new JPasswordField(20);
        box2.add(passwordLabel);
        box2.add(Box.createHorizontalStrut(8));
        box2.add(pasArea);
        Box box3 = Box.createHorizontalBox();
        JButton init = new JButton("Enter");
        init.addActionListener(new buttonInit());
        JButton registr = new JButton("Registration");
        registr.addActionListener(new buttonRegistr());
        box3.add(Box.createHorizontalGlue());
        box3.add(init);
        box3.add(Box.createHorizontalStrut(30));
        box3.add(registr);
        Box box4 = Box.createHorizontalBox();
        JLabel logLabel = new JLabel("Log field:");
        box4.add(logLabel);
        logi = new JTextArea(20,45);
        loginLabel.setPreferredSize(passwordLabel.getPreferredSize());
        Box mainBox = Box.createVerticalBox();
        mainBox.setBorder(new EmptyBorder(12,12,12,12));
        mainBox.add(box1);
        mainBox.add(Box.createVerticalStrut(12));
        mainBox.add(box2);
        mainBox.add(Box.createVerticalStrut(17));
        mainBox.add(box3);
        mainBox.add(Box.createVerticalStrut(17));
        mainBox.add(box4);
        mainBox.add(Box.createVerticalStrut(10));
        mainBox.add(logi);
        setContentPane(mainBox);
        pack();
        setResizable(false);


    }

    class buttonRegistr implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent arg0) {
            String user = logArea.getText();
            String password = pasArea.getText();
            if(user.equals("") || password.equals("")){
                logi.append("Пустое имя пользователя или пароль" + "\n");
                System.exit(2);
            }
            reg(user, password);
            logi.append("Пользователь " + user + " успешно зарегестрирован" + "\n");
            logArea.setText("");
            pasArea.setText("");
        }
    }

    class buttonInit implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent arg0) {
            String user = logArea.getText();
            String password = pasArea.getText();
            if(user.equals("") || password.equals("")){
                logi.append("Пустое имя пользователя или пароль" + "\n");
                System.exit(2);
            }
            log(user, password );
            logi.append("Пользователь " + user + " успешно авторизировался" + "\n");
            logArea.setText("");
            pasArea.setText("");
            logi.append(log(user, password ));
        }
    }



    public static void main(String[] args) {   //запуск потока
        javax.swing.SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                Random r = new Random();
                setN(r.nextInt(1000) + 5000);
                Main frame = new Main();
                frame.pack();
                frame.setLocationRelativeTo(null);
                frame.setVisible(true);
            }

        });


    }

    public static void reg(String user, String password){  //функция регистрации
        Main srpReg = new Main(user, password, getModulus(), 0x02, 256);
        if(saltTable.containsKey(user)){
            System.exit(4);
        }
        saltTable.put(user, srpReg.getSalt());
        verifTable.put(user, srpReg.getVerifier());
    }


    public static String log(String user, String password)
    { // лог авторизации
        Main srpServer = new Main(user, password, getModulus(), 0x02, saltTable.get(user), 128, verifTable.get(user));
        Main srpClient = new Main(user, password, getModulus(), 0x02, srpServer.getSalt());
        srpServer.setSessionKey(true, srpClient.getPublicKey(), null);
        srpClient.setSessionKey(false, srpServer.getPublicKey(), srpServer.getScrambler());
        if(!(srpServer.getSessionKey().equals(srpClient.getSessionKey())))
        {
            System.out.println("Не удалось сгенерировать общий ключ. Сеанс прерван");
            System.exit(3);
        }

        String strm = new String("Salt = " + srpServer.getSalt()+ "\n" + "IdentityHash = " + srpServer.getIdentityHash()+ "\n" +"Verifier = " + srpServer.getVerifier()+ "\n" +"ServerPrivateKey (b)= "
                + srpServer.getPrivateKey()+"\n"+ "ServerPublicKey (B)= " + srpServer.getPublicKey()+"\n"+"Scramber (u)= " + srpServer.getScrambler()+ "\n" +
                "ClientPrivateKey (a) = " + srpClient.getPrivateKey()+ "\n" +"ClientPublicKey (A)= " + srpClient.getPublicKey()+ "\n" +
                "ServerSessionKey = " + srpServer.getSessionKey() + "\n"+"ClientSessionKey = " + srpClient.getSessionKey() + "\n");


        System.out.println("Логи:");
        System.out.println("");
        System.out.println("");
        System.out.println("Modulus = " + srpServer.getModulus());
        System.out.println("Multiplier = " + srpServer.getMultiplier());
        System.out.println("Generator = " + srpServer.getGenerator());
        System.out.println("Salt = " + srpServer.getSalt());
        System.out.println("IdentityHash = " + srpServer.getIdentityHash());
        System.out.println("Verifier = " + srpServer.getVerifier());
        System.out.println("");
        System.out.println("ServerPrivateKey (b)= " + srpServer.getPrivateKey());
        System.out.println("ServerPublicKey (B)= " + srpServer.getPublicKey());
        System.out.println("Scramber (u)= " + srpServer.getScrambler());
        System.out.println("");
        System.out.println("ClientPrivateKey (a) = " + srpClient.getPrivateKey());
        System.out.println("ClientPublicKey (A)= " + srpClient.getPublicKey());
        System.out.println("ClientIdentityHash (x) = " + srpClient.getIdentityHash());
        System.out.println("");
        System.out.println("ServerSessionKey = " + srpServer.getSessionKey());
        System.out.println("ClientSessionKey = " + srpClient.getSessionKey());
        System.out.println("");
        System.out.println("");
        return strm;
    }
    public Main(String user, String password, String modulus_N, int generator_g, String salt, int scramblerBits, String verify) { // Конструктор сервера
        this.modulus_N = new BigInteger(modulus_N, 16);
        this.generator_g = new BigInteger("" + generator_g, 10);
        this.multiplier_k = new BigInteger("3", 10);
        this.salt = new BigInteger(salt, 16);
        this.scrambler = new BigInteger(scramblerBits, new Random());
        sIdentityHash = bytesToBig(hash(bigToByteArray(this.salt), hash(new String(user + ":" + password).getBytes())));
        sVerifier = this.generator_g.modPow(sIdentityHash, this.modulus_N);
        if(!(verify.equals(getVerifier()))){
            System.out.println("Неверный пароль");
            System.exit(5);
        }
        privateKey = new BigInteger(128, new Random());
        publicKey = this.multiplier_k.multiply(sVerifier).add(this.generator_g.modPow( privateKey, this.modulus_N ));
    }


    public Main(String user, String password, String modulus_N, int generator_g, String salt) {  // Конструктор клиента
        this.modulus_N = new BigInteger(modulus_N, 16);
        this.generator_g = new BigInteger("" + generator_g, 10);
        this.multiplier_k = new BigInteger("3", 10);
        this.salt = new BigInteger(salt, 16);
        privateKey = new BigInteger(128, new Random());
        publicKey = this.generator_g.modPow(privateKey, this.modulus_N);
        sIdentityHash = bytesToBig(hash(bigToByteArray(this.salt), hash(new String(user + ":" + password).getBytes())));
    }


    public Main(String user, String password, String modulus_N, int generator_g, int saltBits){ // Конструктор регистрации
        this.modulus_N = new BigInteger(modulus_N, 16);
        this.generator_g = new BigInteger("" + generator_g, 10);
        this.multiplier_k = new BigInteger("3", 10);
        this.salt = new BigInteger(saltBits, new Random());
        sIdentityHash = bytesToBig(hash(bigToByteArray(salt), hash(new String(user + ":" + password).getBytes()))); //идентификационный хэш
        sVerifier = this.generator_g.modPow(sIdentityHash, this.modulus_N);  //верификатор
    }

    public void setSessionKey(boolean server, String pubKeyString, String scram) //общий ключ (отдельно генерятся но равны,если не равны то неверная пара логин пароль)
    {
        BigInteger pubKey = new BigInteger(pubKeyString, 16);
        if (server)
        {
            sessionKey = pubKey.multiply(sVerifier.modPow(scrambler, modulus_N)).modPow(privateKey, modulus_N);
        }
        else {
            this.scrambler = new BigInteger(scram, 16);
            BigInteger temp = privateKey.add(scrambler.multiply(sIdentityHash));
            sessionKey = pubKey.subtract((generator_g.modPow(sIdentityHash, modulus_N)).multiply(multiplier_k)).modPow(temp, modulus_N);
        }
    }

    public String getSessionKey()
    {
        return bytesToHex(bigToByteArray(sessionKey));
    }

    public String getMultiplier()
    {
        return bytesToHex(bigToByteArray(multiplier_k));
    }

    public String getScrambler()
    {
        return bytesToHex(bigToByteArray(scrambler));
    }

    public String getGenerator()
    {
        return bytesToHex(bigToByteArray(generator_g));
    }

    public String getPrivateKey()
    {
        return bytesToHex(bigToByteArray(privateKey));
    }

    public String getPublicKey()
    {
        return bytesToHex(bigToByteArray(publicKey));
    }

    public static String getModulus()
    {
        return bytesToHex(bigToByteArray(N));
    }

    public String getIdentityHash()
    {
        return bytesToHex(bigToByteArray(sIdentityHash));
    }

    public String getSalt()
    {
        return bytesToHex(bigToByteArray(salt));
    }

    public String getVerifier()
    {
        return bytesToHex(bigToByteArray(sVerifier));
    }

    private byte[] hash(byte[] input1)
    {
        return hash(input1, null);
    }
    private byte[] hash(byte[] input1, byte[] input2)
    {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.update(input1);
            if (input2 != null)
                sha.update(input2);
            return sha.digest();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String byteToHex(byte data)
    {
        StringBuffer buf = new StringBuffer();
        buf.append(toHexChar((data>>>4)&0x0F));
        buf.append(toHexChar(data&0x0F));
        return buf.toString();
    }

    private static String bytesToHex(byte[] data) {
        if (data == null)
            return "";
        StringBuffer buf = new StringBuffer();
        data = trim(data);
        for ( int i = 0; i < data.length; i++ )
            buf.append( byteToHex(data[i]) );
        String output = buf.toString();

        return output;
    }

    private static char toHexChar(int i)
    {
        if ((0 <= i) && (i <= 9 ))
            return (char)('0' + i);
        else
            return (char)('a' + (i-10));
    }

    private static byte[] trim(byte[] data) //убирает лишние пробелы и байты(незначащие нули)
    {
        if (data[0] == 0)
        {
            byte[] oldData = data;
            data = new byte[ oldData.length - 1];
            for (int i = 0; i < data.length; i++)
                data[i] = oldData[i + 1];
        }
        return data;
    }

    private static byte[] bigToByteArray(BigInteger bigI)
    {
        if (bigI == null)
            return new byte[] { 0 };

        byte[] temp = bigI.toByteArray();

        if (temp[0] == 0)
        {
            byte[] out = new byte[  temp.length - 1 ];
            for (int i = out.length - 1; i >= 0; i--)
                out[i] = temp[i + 1];

            return out;
        }

        return temp;
    }

    private static BigInteger bytesToBig(byte[] bytes)
    {
        return new BigInteger(bytesToHex(bytes), 16);
    }

    public static BigInteger setN(long number) {
        List<Long> numbers = new ArrayList<>();
        long st = 0;
        long n = 3;
        long a = 0;
        numbers.add((long) 2);
        while (st < number) {
            for (int i = 0; i < numbers.size(); i++) {
                if (n % numbers.get(i) == 0) {
                    break;
                }
                if (numbers.get(i) >= Math.sqrt(n)) {
                    st++;
                    numbers.add(n);
                    break;
                }
            }
            n += (long) 2;
        }
        for (int i = 0; i < numbers.size(); i++) {
            a = numbers.get(i);
            for (int j = numbers.size() - 2; j > 0; j--) {
                if (a == 2 * numbers.get(j) - 1) {
                    break;
                }
            }
        }
        N = BigInteger.valueOf(a);
        return N;
    }




}
