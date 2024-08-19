import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

/**
 * Class implementing cryptographic operations based on pairing-based cryptography (PBC),
 * following the CL encryption scheme described in the paper:
 * Reference:
 * - G. Castagnos and F. Laguillaumie, “Linearly homomorphic encryption from DDH,” in CT-RSA, 2015, pp. 487–505.
 * Available at: <a href="https://eprint.iacr.org/2015/047.pdf">...</a>
 * This class provides methods for CL encryption, homomorphic multiplication, and addition.
 *
 * @author shiyang
 */
public class ClEncryption {
    /**
     * TypeA1 curve supports fields of composite order.
     * Type A1 curve requires two parameters:
     * numPrimes, which is the number of prime factors in the order N;
     * bits, which is the bit length of each prime factor.
     */
    public static TypeA1CurveGenerator pg = new TypeA1CurveGenerator(2, 128);
    public static PairingParameters typeA1Params = pg.generate();
    public static Pairing pairing = PairingFactory.getPairing(typeA1Params);
    /**
     * Since the elliptic curve forms an additive group, any element in the group G can be chosen as a generator.
     */
    public static Element generator = pairing.getG1().newRandomElement().getImmutable();
    /**
     * Generate the generator f of group F, where the order of F is known.
     */
    public static Element f = ElementUtils.getGenerator(pairing, generator, typeA1Params, 0, 2).getImmutable();
    /**
     * Generate the generator gq of group Gq, where the order of Gq is unknown.
     */
    public static Element gq = ElementUtils.getGenerator(pairing, generator, typeA1Params, 1, 2).getImmutable();
    /**
     * The secret key sk and the corresponding public key pk for the CL encryption scheme.
     * pk = gq^sk.
     */
    public static Element sk = pairing.getZr().newRandomElement().getImmutable();
    public static Element pk = gq.powZn(sk);

    /**
     * Main method to demonstrate encryption, homomorphic operations (multiplication and addition),
     * and decryption with the CL encryption scheme.
     */
    public static void main(String[] args) {
        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element b = pairing.getZr().newRandomElement().getImmutable();

        // Encrypt values a and b
        Element[] encA = clEncrypt(a);
        Element[] encB = clEncrypt(b);

        // Compute encrypted product ab using homomorphic multiplication
        Element[] enc1 = mulHom(a, encB);

        // Compute encrypted sum (a + b) using homomorphic addition
        Element[] enc2 = addHom(encA, encB);

        // Decrypt the encrypted values for validation
        System.out.println(f.powZn(a));
        System.out.println(clDecrypt(encA));
        System.out.println(f.powZn(b));
        System.out.println(clDecrypt(encB));

        // Validate homomorphic multiplication
        System.out.println(f.powZn(a.mul(b)));
        System.out.println(clDecrypt(enc1));
        // Validate homomorphic addition
        System.out.println(f.powZn(a.add(b)));
        System.out.println(clDecrypt(enc2));
    }

    /**
     * Encrypts a message m using CL encryption scheme, which outputs
     * (gq^r, f^m * pk^r).
     *
     * @param m The message to encrypt
     * @return The encrypted message as an array of Elements [c1, c2]
     */
    public static Element[] clEncrypt(Element m){
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element c1 = gq.powZn(r);
        Element c2 = f.powZn(m).mul(pk.powZn(r));
        return new Element[]{c1,c2};
    }

    /**
     * Homomorphic scalar multiplication operation, producing
     * (gq^ar, f^(ab) * pk^ar).
     *
     * @param a The scalar value a
     * @param encB The encrypted value of message b
     * @return The encrypted result of ab as an array of Elements [c1, c2]
     */
    public static Element[] mulHom(Element a, Element[] encB){
        Element c1 = encB[0].powZn(a);
        Element c2 = encB[1].powZn(a);
        return new Element[]{c1,c2};
    }

    /**
     * Homomorphic addition of two encrypted values, producing
     * the encrypted result of (a + b).
     *
     * @param encA The encrypted value of a
     * @param encB The encrypted value of b
     * @return The encrypted result of (a + b) as an array of Elements [c1, c2]
     */
    public static Element[] addHom(Element[] encA, Element[] encB){
        // c1 = gq^r1 * gq^r2 => gq^(r1+r2)
        Element c1 = encA[0].mul(encB[0]);
        // c2 = f^a * pk^r1 * f^b * pk^r2 => f^(a+b) * pk^(r1+r2)
        Element c2 = encA[1].mul(encB[1]);
        return new Element[]{c1,c2};
    }

    /**
     * Decrypts the encrypted value to retrieve the original message m.
     *
     * @param encM The encrypted value of m
     * @return The decrypted value f^m
     */
    public static Element clDecrypt(Element[] encM){
        Element temp = encM[0].powZn(sk);
        return encM[1].mul(temp.invert());
    }
}
