import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class NotesPasswordManager {
    private static final String NOTES_FILE = "notes.txt";
    private static final String PASSWORDS_FILE = "passwords.dat";
    private static SecretKey secretKey;
    private static final Map<String, String> passwordMap = new HashMap<>();
    
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        secretKey = generateKey();
        loadPasswords();
        
        while (true) {
            System.out.println("\n1. Add Note\n2. View Notes\n3. Save Password\n4. Retrieve Password\n5. Exit\nChoose an option: ");
            int choice = scanner.nextInt();
            scanner.nextLine();
            
            switch (choice) {
                case 1:
                    addNote(scanner);
                    break;
                case 2:
                    viewNotes();
                    break;
                case 3:
                    savePassword(scanner);
                    break;
                case 4:
                    retrievePassword(scanner);
                    break;
                case 5:
                    savePasswords();
                    System.out.println("Exiting...");
                    return;
                default:
                    System.out.println("Invalid choice, try again.");
            }
        }
    }
    
    private static void addNote(Scanner scanner) throws IOException {
        System.out.println("Enter your note:");
        String note = scanner.nextLine();
        try (FileWriter writer = new FileWriter(NOTES_FILE, true)) {
            writer.write(note + "\n");
        }
        System.out.println("Note saved successfully.");
    }
    
    private static void viewNotes() throws IOException {
        File file = new File(NOTES_FILE);
        if (!file.exists()) {
            System.out.println("No notes available.");
            return;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(NOTES_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("- " + line);
            }
        }
    }
    
    private static void savePassword(Scanner scanner) throws Exception {
        System.out.println("Enter website or account name:");
        String account = scanner.nextLine();
        System.out.println("Enter password:");
        String password = scanner.nextLine();
        String encryptedPassword = encrypt(password);
        passwordMap.put(account, encryptedPassword);
        System.out.println("Password saved successfully.");
    }
    
    private static void retrievePassword(Scanner scanner) throws Exception {
        System.out.println("Enter website or account name:");
        String account = scanner.nextLine();
        if (passwordMap.containsKey(account)) {
            String decryptedPassword = decrypt(passwordMap.get(account));
            System.out.println("Password: " + decryptedPassword);
        } else {
            System.out.println("No password found for this account.");
        }
    }
    
    private static void loadPasswords() {
        File file = new File(PASSWORDS_FILE);
        if (!file.exists()) return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
            Map<String, String> savedPasswords = (Map<String, String>) ois.readObject();
            passwordMap.putAll(savedPasswords);
        } catch (Exception e) {
            System.out.println("Error loading passwords.");
        }
    }
    
    private static void savePasswords() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(PASSWORDS_FILE))) {
            oos.writeObject(passwordMap);
        } catch (IOException e) {
            System.out.println("Error saving passwords.");
        }
    }
    
    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, new SecureRandom());
        return keyGen.generateKey();
    }
    
    private static String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }
    
    private static String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decodedData));
    }
}
