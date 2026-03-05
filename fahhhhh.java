class Node {
    int data;
    Node next;

    public Node(int data) {
        this.data = data;
        this.next = null;
    }
}
public class fahhhhh {
    static Node Middle ( Node head){
        if(head == null) return null;
        Node slow = head;
        Node fast = head;
        while(fast != null && fast.next != null){
            slow = slow.next;
            fast = fast.next.next;
        }
        return slow;
    }
    public static void main(String[] args) {
        Node head = new Node(10);
        head.next = new Node(20);
        head.next.next = new Node(30);
        head.next.next.next = new Node(40);
        head.next.next.next.next = new Node(50);

        Node middleNode = Middle(head);
        if (middleNode != null) {
            System.out.println("Middle node data: " + middleNode.data);
        } else {
            System.out.println("The linked list is empty.");

            
        }
    }
}