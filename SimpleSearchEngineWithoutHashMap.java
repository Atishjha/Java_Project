import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class SimpleSearchEngineWithoutHashMap {

    // Array to store documents
    private static String[] documents = new String[10];
    private static int documentCount = 0;

    // Inverted index: a list of words and associated document IDs
    private static List<String> words = new ArrayList<>();
    private static List<List<Integer>> documentIds = new ArrayList<>();

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Add some documents
        addDocument("Java is a high-level programming language.");
        addDocument("Python is popular for data science and AI.");
        addDocument("Java is widely used for backend development.");
        addDocument("Search engines use indexing and ranking algorithms.");

        System.out.println("Welcome to the Simple Search Engine!");
        System.out.println("Enter a keyword to search (or type 'exit' to quit):");

        while (true) {
            System.out.print("\nSearch: ");
            String query = scanner.nextLine().toLowerCase();

            if (query.equals("exit")) {
                System.out.println("Goodbye!");
                break;
            }

            List<Integer> results = search(query);
            if (results.isEmpty()) {
                System.out.println("No results found for '" + query + "'.");
            } else {
                System.out.println("Found in documents:");
                for (int docId : results) {
                    System.out.println("Document " + (docId + 1) + ": " + documents[docId]);
                }
            }
        }

        scanner.close();
    }

    // Add a document to the array and index it
    private static void addDocument(String content) {
        if (documentCount >= documents.length) {
            System.out.println("Error: Maximum document limit reached.");
            return;
        }
        documents[documentCount] = content;
        indexDocument(documentCount, content);
        documentCount++;
    }

    // Index a document (populate the inverted index)
    private static void indexDocument(int id, String content) {
        String[] tokens = content.toLowerCase().split("\\W+");
        for (String token : tokens) {
            int index = words.indexOf(token);
            if (index == -1) {
                // Word not in the index, add it
                words.add(token);
                List<Integer> docList = new ArrayList<>();
                docList.add(id);
                documentIds.add(docList);
            } else {
                // Word already in the index, add the document ID if not already present
                List<Integer> docList = documentIds.get(index);
                if (!docList.contains(id)) {
                    docList.add(id);
                }
            }
        }
    }

    // Search for a word in the inverted index
    private static List<Integer> search(String keyword) {
        List<Integer> results = new ArrayList<>();
        int index = words.indexOf(keyword);
        if (index != -1) {
            results = documentIds.get(index);
        }
        return results;
    }
}
