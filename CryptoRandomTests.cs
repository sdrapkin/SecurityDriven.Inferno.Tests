using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SecurityDriven.Inferno.Tests
{
	/// <summary>
	/// Tests borrowed from
	/// https://github.com/dotnet/corefx/blob/master/src/System.Security.Cryptography.RandomNumberGenerator/tests/RandomNumberGeneratorTests.cs
	/// </summary>
	[TestClass]
	public class CryptoRandomTests
	{
		static void AssertNeutralParity(byte[] random)
		{
			int oneCount = 0;
			int zeroCount = 0;

			for (int i = 0; i < random.Length; ++i)
			{
				for (int j = 0; j < 8; ++j)
				{
					if (((random[i] >> j) & 1) == 1)
					{
						++oneCount;
					}
					else
					{
						++zeroCount;
					}
				}
			}

			int totalCount = zeroCount + oneCount;
			float bitDifference = (float)Math.Abs(zeroCount - oneCount) / totalCount;

			// Over the long run there should be about as many 1s as 0s.
			// This isn't a guarantee, just a statistical observation.
			// Allow a 6% tolerance band before considering it to have gotten out of hand.
			Assert.IsTrue(bitDifference < 0.06, bitDifference.ToString());
		}

		[TestMethod]
		public void CryptoRandom_DifferentSequential_10()
		{
			DifferentSequential(10);
		}

		[TestMethod]
		public void CryptoRandom_DifferentSequential_256()
		{
			DifferentSequential(256);
		}

		[TestMethod]
		public void CryptoRandom_DifferentSequential_65536()
		{
			DifferentSequential(65536);
		}

		[TestMethod]
		public void CryptoRandom_DifferentParallel_10()
		{
			DifferentParallel(10);
		}

		[TestMethod]
		public void CryptoRandom_DifferentParallel_256()
		{
			DifferentParallel(256);
		}

		[TestMethod]
		public void CryptoRandom_DifferentParallel_65536()
		{
			DifferentParallel(65536);
		}

		[TestMethod]
		public void CryptoRandom_NeutralParity()
		{
			byte[] random = new byte[2048];

			var rng = new CryptoRandom();
			rng.NextBytes(random);

			AssertNeutralParity(random);
		}

		[TestMethod]
		public void CryptoRandom_IdempotentDispose()
		{
			// CryptoRandom doesn't need to be disposed
			Assert.IsTrue(true);
		}

		[TestMethod]
		public void CryptoRandom_NullInput1()
		{
			var rng = new CryptoRandom();
			try
			{
				rng.NextBytes(null); // should throw
			}
			catch (NullReferenceException)
			{
				Assert.IsTrue(true);
				return;
			}
			Assert.Fail("Failed to throw NullReferenceException.");
		}

		[TestMethod]
		public void CryptoRandom_NullInput2()
		{
			var rng = new CryptoRandom();
			try
			{
				rng.NextBytes(null, 0, 0); // should throw
			}
			catch (ArgumentNullException)
			{
				Assert.IsTrue(true);
				return;
			}
			Assert.Fail("Failed to throw ArgumentNullException.");
		}

		[TestMethod]
		public void CryptoRandom_ZeroLengthInput()
		{
			var rng = new CryptoRandom();

			// While this will do nothing, it's not something that throws.
			rng.NextBytes(Utils.ZeroLengthArray<byte>.Value);
			rng.NextBytes(Utils.ZeroLengthArray<byte>.Value, 0, 0);

			bool isThrown = false;
			try
			{
				rng.NextBytes(Utils.ZeroLengthArray<byte>.Value, 0, 123);
			}
			catch (ArgumentException) { isThrown = true; }
			Assert.IsTrue(isThrown);

			isThrown = false;
			try
			{
				rng.NextBytes(Utils.ZeroLengthArray<byte>.Value, 123, 0);
			}
			catch (ArgumentException) { isThrown = true; }
			Assert.IsTrue(isThrown);
		}

		[TestMethod]
		public void CryptoRandom_ConcurrentAccess()
		{
			const int ParallelTasks = 16;
			const int PerTaskIterationCount = 20;
			const int RandomSize = 1024;

			var tasks = new System.Threading.Tasks.Task[ParallelTasks];
			byte[][] taskArrays = new byte[ParallelTasks][];

			var rng = new CryptoRandom();
			using (var sync = new System.Threading.ManualResetEvent(false))
			{
				for (int iTask = 0; iTask < ParallelTasks; iTask++)
				{
					taskArrays[iTask] = new byte[RandomSize];
					byte[] taskLocal = taskArrays[iTask];

					tasks[iTask] = System.Threading.Tasks.Task.Run(
						() =>
						{
							sync.WaitOne();

							for (int i = 0; i < PerTaskIterationCount; i++)
							{
								rng.NextBytes(taskLocal);
							}
						});
				}

				// Ready? Set() Go!
				sync.Set();
				System.Threading.Tasks.Task.WaitAll(tasks);
			}

			for (int i = 0; i < ParallelTasks; i++)
			{
				// The Real test would be to ensure independence of data, but that's difficult.
				// The other end of the spectrum is to test that they aren't all just new byte[RandomSize].
				// Middle ground is to assert that each of the chunks has neutral(ish) bit parity.
				AssertNeutralParity(taskArrays[i]);
			}
		}

		static void DifferentSequential(int arraySize)
		{
			// Ensure that the RNG doesn't produce a stable set of data.
			byte[] first = new byte[arraySize];
			byte[] second = new byte[arraySize];

			var rng = new CryptoRandom();
			rng.NextBytes(first);
			rng.NextBytes(second);

			// Random being random, there is a chance that it could produce the same sequence.
			// The smallest test case that we have is 10 bytes.
			// The probability that they are the same, given a Truly Random Number Generator is:
			// Pmatch(byte0) * Pmatch(byte1) * Pmatch(byte2) * ... * Pmatch(byte9)
			// = 1/256 * 1/256 * ... * 1/256
			// = 1/(256^10)
			// = 1/1,208,925,819,614,629,174,706,176
			Assert.AreNotEqual(first, second);
		}

		static void DifferentParallel(int arraySize)
		{
			// Ensure that two RNGs don't produce the same data series (such as being implemented via new Random(1)).
			byte[] first = new byte[arraySize];
			byte[] second = new byte[arraySize];

			var rng1 = new CryptoRandom();
			var rng2 = new CryptoRandom();

			rng1.NextBytes(first);
			rng2.NextBytes(second);

			// Random being random, there is a chance that it could produce the same sequence.
			// The smallest test case that we have is 10 bytes.
			// The probability that they are the same, given a Truly Random Number Generator is:
			// Pmatch(byte0) * Pmatch(byte1) * Pmatch(byte2) * ... * Pmatch(byte9)
			// = 1/256 * 1/256 * ... * 1/256
			// = 1/(256^10)
			// = 1/1,208,925,819,614,629,174,706,176
			Assert.AreNotEqual(first, second);
		}
	}//class CryptoRandomTests
}//ns