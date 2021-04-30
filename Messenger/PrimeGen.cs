/// Author: Chengyi Ma, cxm3593
/// CSCI 251 Project 2
/// This program generates potential prime numbers from given input
using System;
using System.Numerics;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Collections.Generic;

namespace PrimeGen
{
    /// <summary>
    /// The main class that runs the application with main method.
    /// </summary>
    class Program
    {
        /// <summary>
        /// Main method, program entry
        /// </summary>
        /// <param name="args">Command lind arguments: bits = args[0], count = args[1]</param>
        static void Main(string[] args)
        {
            int bits = 0;
            int count = 1;

            if (args.Length > 2 || args.Length < 1)
            {
                printHelp();
            }
            else 
            {
                try {
                    bits = int.Parse(args[0]);
                    if(args.Length == 2)
                    {
                        count = int.Parse(args[1]);
                    }
                }
                catch(Exception e)
                {
                    Console.WriteLine(e.Message);
                    printHelp();
                }
            }
            
            // Check if the bits meet the requirment
            if(bits < 32 || (bits % 8 != 0))
            {
                printHelp();
                System.Environment.Exit(0);
            }
            
            // Check if the count is valid
            if(count <= 0)
            {
                printHelp();
                System.Environment.Exit(0);
            }

            Console.WriteLine("BitLength: {0} bits; ", bits);

            // Set the bits and count for PrimeSeeker
            PrimeSeeker.bits = bits;
            PrimeSeeker.count = count;

            ParallelPrimeGen pp = new ParallelPrimeGen(count);
            pp.generate();


        }

        private static void printHelp()
        {
            Console.WriteLine("dotnet run <bits> <count=1>");
            Console.WriteLine("\t- bits - the number of bits of the prime number, this must be a multiple of 8, and at least 32 bits.");
            Console.WriteLine("\t- count - the number of prime numbers to generate, defaults to 1");
        }

        
    }

    /// <summary>
    /// This class provide help with generating numbers in parallel
    /// It generates PrimeSeeker which handles a single number
    /// </summary>
    class ParallelPrimeGen
    {
        int target; // how many we want in result
        int count = 0; // how many have been found so far

        static object count_key = new object();
        static Stopwatch sw = new Stopwatch();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="target"></param>
        public ParallelPrimeGen(int target) 
        {
            this.target = target;
        }

        /// <summary>
        /// Generates PrimeSeekers for prime numbers in parallel.
        /// </summary>
        public void generate()
        {
            sw.Start();
            Parallel.For(0, Int32.MaxValue, id => 
            {
                PrimeSeeker ps = new PrimeSeeker();
                bool result = ps.seek();
                if (result)
                {

                    lock (count_key)
                    {
                        this.count += 1;
                        Console.WriteLine("{0}: {1}", this.count, ps.candidate_prime);
                        if (this.count == this.target)
                        {
                            sw.Stop();
                            Console.WriteLine("Time to Generate: {0}", sw.Elapsed);
                            System.Environment.Exit(0);
                        }
                        else
                        {
                            Console.WriteLine();
                        }
                    }
                }
            });
        }

        /// <summary>
        /// This is auxiliary method for project3 to generate prime numbers
        /// </summary>
        /// <returns>List<BigInteger> : prime numbers </returns>
        public List<BigInteger> generate_silent()
        {
            List<BigInteger> prime_numbers = new List<BigInteger>();
            Parallel.For(0, Int32.MaxValue, (id, state) =>
            {
                PrimeSeeker ps = new PrimeSeeker();
                bool result = ps.seek();

                if (result)
                {
                    lock (count_key)
                    {
                        
                        if (this.count == this.target)
                        {
                            state.Break();
                        }
                        else
                        {
                            this.count += 1;
                            prime_numbers.Add(ps.candidate_prime);
                        }
                    }
                }
            });

            return prime_numbers;
        }


    }

    /// <summary>
    /// This class uses provided algorithm to help predict prime
    /// </summary>
    public static class PrimeHelper
    {

        /// <summary>
        /// The help method checks if a value is probably prime number
        /// </summary>
        /// <param name="value">the value to be checked</param>
        /// <param name="witnesses">How many witnesses need for getting a result</param>
        /// <returns></returns>
        public static Boolean IsProbablyPrime(this BigInteger value, int witnesses = 10)
        {
            if (value <= 1) return false;
            if (witnesses <= 0) witnesses = 10;
            BigInteger d = value - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            Byte[] bytes = new Byte[value.ToByteArray().LongLength];
            BigInteger a;
            for (int i = 0; i < witnesses; i++)
            {
                do
                {
                    var Gen = new Random();
                    Gen.NextBytes(bytes);
                    a = new BigInteger(bytes);
                } while (a < 2 || a >= value - 2);
                BigInteger x = BigInteger.ModPow(a, d, value);
                if (x == 1 || x == value - 1) continue;
                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, value);
                    if (x == 1) return false;
                    if (x == value - 1) break;
                }
                if (x != value - 1) return false;
            }
            return true;
        }
    }

    /// <summary>
    /// PrimeSeeker generates a random number and check if it is a prime number
    /// </summary>
    class PrimeSeeker
    {
        
        public static int bits { get; set; }
        public static int count { get; set; }
        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

        public Byte[] container { get; private set; }
        public BigInteger candidate_prime { get; private set; }
        public bool isPrime { get; private set; }


        /// <summary>
        /// Constructor
        /// </summary>
        public PrimeSeeker()
        {
            container = new Byte[bits / 8];
            rngCsp.GetBytes(container);
            candidate_prime = BigInteger.Abs(new BigInteger(container));
            
        }

        /// <summary>
        /// checks if the number generated within the class is a prime and return the bool result
        /// </summary>
        /// <returns>bool: true if the number is predicted to be a prime</returns>
        public bool seek()
        {
            bool result = candidate_prime.IsProbablyPrime();

            this.isPrime = result;

            return result;
        }
    }

    


}
