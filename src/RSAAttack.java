import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Random;

public class RSAAttack {
	
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////
    // Prime random numbers generation	
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	
	static Random gRandomGen = new Random();
	
	public static BigInteger generateRandomNumber(int numBits) {
		//System.out.println("number of bits = " + numBits);
		// Constructs a randomly generated BigInteger, uniformly distributed over the range 0 to (2^numBits - 1), inclusive.
		return new BigInteger(numBits, 10, gRandomGen);
	}
	
	// Test Miller-Rabin
    public static boolean testPrimeNumber(BigInteger p) {       
        // step 0
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        ///System.out.println("Test Miller-Rabin: Step 0:");
        ///System.out.println("Test Miller-Rabin: p - 1 = " + pMinus1.toString());
        // find s
        int s = 0;
        // divide by 2
        while (pMinus1.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
        	s++;
        	pMinus1 = pMinus1.divide(BigInteger.TWO);
        }
        BigInteger d = pMinus1;
        ///System.out.println("Test Miller-Rabin: d = " + d.toString());
        ///System.out.println("Test Miller-Rabin: s = " + s);
        
        pMinus1 = p.subtract(BigInteger.ONE); // refresh value
        
        for (int k = 1; k < 10; k++) {
	        // step 1
	        ///System.out.println("Test Miller-Rabin: step 1, k = " + k);
	        BigInteger x = generateRandomNumber(p.bitLength());
	        
	        if (x.equals(BigInteger.ZERO) || x.equals(BigInteger.ONE) || x.equals(pMinus1)) {
//	        	System.out.println("Test Miller-Rabin 1: bad number - generate one more time");
	        	continue;
	        }
	        
	        BigInteger resGcd = x.gcd(p);
	        if (!resGcd.equals(BigInteger.ONE)) {
//	        	System.out.println("Test Miller-Rabin 1: number failed - not prime");
	        	return false;
	        }
	        
	        // step 2
	        ///System.out.println("Test Miller-Rabin: step 2");
	        BigInteger x_r = x.modPow(d, p);
	        //System.out.println("Test Miller-Rabin 2: x_r = " + x_r.toString());
	        // step 2.1
	        if (x_r.equals(BigInteger.ONE) || x_r.equals(pMinus1)) {
	        	//System.out.println("Test Miller-Rabin 2.1: number is pseudosimple : x^d = +-1(mod p)");
	        } else {
		        // step 2.2
		        for (int r = 1; r < s; r++) {
		        	x_r = x_r.modPow(BigInteger.TWO, p);
		        	
		        	if (x_r.equals(pMinus1)) {
			        	///System.out.println("Test Miller-Rabin 2.2: number is pseudosimple : x^(d*2^r) = -1(mod p)");
			        	continue;
		        	}
		        	
		        	if (x_r.equals(BigInteger.ONE)) {
		        		///System.out.println("Test Miller-Rabin 2.2: number failed - not prime, r = " + r);
		        		return false;
		        	}
		        }
		        ///System.out.println("Test Miller-Rabin: number failed - not prime. Step 2.1 and 2.2 failed");
		        ///System.out.println("Test Miller-Rabin: x_r = " + x_r.toString());
		        return false;
	        }
	    
        }
        
        return true;
    }
	
	public static BigInteger generatePrimeNumber(int numBits) {
		BigInteger newRndNumber = BigInteger.TWO; // just to avoid errors - set NOT prime number 
		boolean isPrime = false;
		
		while (isPrime == false) {
			newRndNumber = generateRandomNumber(numBits);
//			System.out.println("generatePrimeNumber: posible prime number " + newRndNumber.toString(16));
			isPrime = testPrimeNumber(newRndNumber);
		}
		//System.out.println("generatePrimeNumber: new random prime number = " + newRndNumber.toString(16));
		return newRndNumber;
	}
	
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////
    // RSA functions
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	
//   public static ArrayList<BigInteger> GenerateKeyPair(BigInteger p, BigInteger q) {
     public static ArrayList<BigInteger> GenerateKeyPair(BigInteger p, BigInteger q, int e_lenght) {
    	BigInteger n = p.multiply(q);
    	BigInteger funOylera = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
//    	BigInteger e = BigInteger.TWO.pow(16).add(BigInteger.ONE);
    	BigInteger e = null;
    	boolean genE = false;
    	while (genE == false) {
    		e = generatePrimeNumber(e_lenght);
    		if (e.compareTo(BigInteger.ONE) == 1 && e.compareTo(funOylera) == -1 && e.gcd(funOylera).equals(BigInteger.ONE) == true) {
    			genE = true; 
    		} else {
    			continue;
    		} 
    	}   
    	BigInteger d = e.modInverse(funOylera); 
    	  	
    	ArrayList<BigInteger> keys = new ArrayList<BigInteger>();
    	keys.add(n); // index 0 - public Key
    	keys.add(e); // index 1 - public Key
    	keys.add(d); // index 2 - private Key
    	return keys;
    }
      
    public static BigInteger Encrypt(BigInteger M, BigInteger pubKeyE, BigInteger n) {
        return M.modPow(pubKeyE, n);
    }

    public static BigInteger Decrypt(BigInteger C, BigInteger privKeyD, BigInteger n) {
        return C.modPow(privKeyD, n);
    }
    
    public static void meet_in_middle(BigInteger e, BigInteger n, BigInteger C) {
		int l = 256 - 216;
//		System.out.println("Attack: l  = " + l);
		//System.out.println("Attack: l  = " + );
		HashMap<BigInteger,BigInteger> X_st = new HashMap<BigInteger,BigInteger>();
		HashMap<BigInteger,BigInteger> X_st2 = new HashMap<BigInteger,BigInteger>();
		BigInteger end = BigInteger.TWO.pow(l/2).add(BigInteger.ONE);
		BigInteger start = BigInteger.ONE;
		
		while (!start.equals(end)) {
			BigInteger t = start;
			X_st.put(t, t.modPow(e, n));
			X_st2.put(t.modPow(e, n), t);
			start = start.add(BigInteger.ONE);
		}
//		System.out.println("Attack: X' i X'' created ");
		
		BigInteger y_s = null;
		start = BigInteger.ONE;
		while (!start.equals(end)) {
			BigInteger s_e = X_st.get(start);
			y_s = s_e.modInverse(n);
			y_s = C.multiply(y_s).mod(n);
			
			if (X_st2.containsKey(y_s)) {
				BigInteger C_x_1 = start;
				BigInteger C_x_2 = X_st2.get(y_s);
//				System.out.println("Attack: s(x1) = " + C_x_1.toString(16));
//				System.out.println("Attack: t(x2) = " + C_x_2.toString(16));
//				System.out.println("Attack: y = (st)^e mod n = " + C_x_1.multiply(C_x_2).modPow(e, n).toString(16));
				break;
			}
			start = start.add(BigInteger.ONE);
		}
		if (start.equals(end)) {
//			System.out.println("Attack: s, t not found");
		}
		
//		System.out.println("Attack: done");		
    }
       
	public static void main(String[] args) {
	
			
		// Generate p,q
		BigInteger p, q;
		while (true) {
		p = generatePrimeNumber(256);
		q = generatePrimeNumber(256);
		int temp = q.compareTo(p);
		int temp2 = p.compareTo(BigInteger.TWO.multiply(q));
			if (temp == -1 | temp2 == -1) {
				break;
			}
		} 
//		BigInteger p = new BigInteger("8e4efc3e972aa169a40d5dc16edd7c7f", 16);
//		BigInteger q = new BigInteger("f44bf0ab9a9f1a45287dfc466b06deb7", 16);

     	for (int e_lenght = 2; e_lenght < 1025; e_lenght = e_lenght*2) {
    		double average_one_lenght_count = 0;
     		for (int j = 0; j < 5; j++) {
//				System.out.println("");
//				System.out.println("");
				ArrayList<BigInteger> keys = GenerateKeyPair(p, q, e_lenght);
	//			ArrayList<BigInteger> keys = GenerateKeyPair(p, q);
				BigInteger pubKey_n = keys.get(0);
				BigInteger pubKey_e = keys.get(1);
				BigInteger privKey_d = keys.get(2);
//				System.out.println("RSA: private key part: p  = " + p.toString(16));
//				System.out.println("RSA: private key part: q  = " + q.toString(16));
//				System.out.println("RSA: private key: d  = " + privKey_d.toString(16));
//				System.out.println("RSA: public key: e  = " + pubKey_e.toString(16));
//				System.out.println("RSA: public key: n  = " + pubKey_n.toString(16));
				
				
				System.out.println("");
//				System.out.println("Test Encrypt / Decrypt");
				BigInteger x_1 = new BigInteger("7B8B", 16);
				BigInteger x_2 = new BigInteger("CEB7", 16);
				BigInteger M = x_1.multiply(x_2);
				BigInteger C = Encrypt(M, pubKey_e, pubKey_n);
				BigInteger M_dec = Decrypt(C, privKey_d, pubKey_n); 
				
//				System.out.println("RSA: x_1  = " + x_1.toString(16));
//				System.out.println("RSA: x_2  = " + x_2.toString(16));
//				System.out.println("RSA: open text (x_1*x_2)  = " + M.toString(16));
//				System.out.println("RSA: ciphertext  = " + C.toString(16));
//				System.out.println("RSA: decrypted text  = " + M_dec.toString(16));
						    	
				double count = 0;
				for (int i = 0; i < 2; i++ ) {
					long m = System.currentTimeMillis();  
					meet_in_middle(pubKey_e, pubKey_n, C);
//					System.out.println("Time of one work in miliseconds: ");
					System.out.println((double) (System.currentTimeMillis() - m));
					count = count + System.currentTimeMillis() - m;
				}
				double average_personal = count/2;
//				System.out.println("Average time of attack for personal e in miliseconds: " + average_personal);
				average_one_lenght_count  = average_one_lenght_count + average_personal;
	     	}
     		average_one_lenght_count = average_one_lenght_count/5;
     		System.out.println("Average time of attack for one lenght e: " + e_lenght + " in miliseconds: " + average_one_lenght_count);
		}
	}

}

	
	



