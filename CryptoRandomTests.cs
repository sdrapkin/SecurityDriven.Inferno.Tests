using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading.Tasks;
using System.Linq;

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
		public void CryptoRandom_NextDouble()
		{
			Func<decimal, int, decimal> bucketFn = (val, _bucketCount) =>
			{
				if (val < 0M) return decimal.MinValue / 4;
				if (val >= 1M) return decimal.MaxValue / 2;

				decimal step = 1M / _bucketCount, m = step;
				for (int i = 0; i < _bucketCount - 1; ++i, m += step)
				{
					if (val < m) return m;
				}
				return m;
			};

			var rng = new CryptoRandom();
			Func<decimal> decimalFn = () => (decimal)rng.NextDouble();

			const int bucketCount = 200;

			const int extra_count1 = 0;
			const int extra_count2 = 0;
			const int count = 40000 * 1;
			const int totalCount = count + extra_count1 + extra_count2;

			var q1 = Enumerable.Range(0, count).Select(i => decimalFn())
				.Concat(Enumerable.Repeat(0.1M, extra_count1))
				.Concat(Enumerable.Repeat(0.9M, extra_count2)).ToList();

			var q2 = q1.AsParallel().GroupBy(val => bucketFn(val, bucketCount));
			var q3 = q2.Select(d => new { Key = d.Key, Count = d.LongCount() });

			decimal expectedMaxAverageDelta = (1M / ((decimal)Math.Pow(totalCount, 1d / 2.5)));

			decimal actualAverage = q1.Average();
			decimal actualAverageDelta = Math.Abs(actualAverage - 0.5M);
			Assert.IsTrue(actualAverageDelta < expectedMaxAverageDelta, $"Unexpected average delta: {actualAverageDelta} {expectedMaxAverageDelta}");

			decimal keySum = decimal.Round(q3.Sum(i => i.Key), 2);
			Assert.IsTrue(keySum > 0);
			Assert.IsTrue(keySum < bucketCount);

			var expectedKeySum = decimal.Round((1M + bucketCount) / 2, 2);
			Assert.IsTrue(keySum == expectedKeySum, $"Unexpected bucket key sum: {keySum} expected: {expectedKeySum}");

			var avg = q3.Select(i => i.Count).Average();
			var sumOfSquares = (from i in q3 let delta = (i.Count - avg) select delta * delta).Sum();
			var stddev = Math.Sqrt(sumOfSquares / q3.Count());

			var q4 = q3.Select(i => Math.Abs(i.Count - avg));

			decimal stddevTest1 = 0M, stddevTest2 = 0M, stddevTest3 = 0M;
			foreach (var val in q4)
			{
				if (val < stddev * 1) ++stddevTest1;
				if (val < stddev * 2) ++stddevTest2;
				if (val < stddev * 3) ++stddevTest3;
			}

			stddevTest1 = decimal.Round(stddevTest1 / bucketCount, 2);
			stddevTest2 = decimal.Round(stddevTest2 / bucketCount, 2);
			stddevTest3 = decimal.Round(stddevTest3 / bucketCount, 2);

			Assert.IsTrue(Math.Abs(stddevTest1 - 0.68M) <= 0.04M, $"{nameof(stddevTest1)} failed: {stddevTest1}"); // target: 0.68
			Assert.IsTrue(Math.Abs(stddevTest2 - 0.95M) <= 0.04M, $"{nameof(stddevTest2)} failed: {stddevTest2}"); // target: 0.95
			Assert.IsTrue(Math.Abs(stddevTest3 - 0.99M) <= 0.04M, $"{nameof(stddevTest3)} failed: {stddevTest3}"); // target: 0.99
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

		//[TestMethod]
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

					tasks[iTask] = Task.Factory.StartNew(
						() =>
						{
							sync.WaitOne();

							for (int i = 0; i < PerTaskIterationCount; i++)
							{
								rng.NextBytes(taskLocal);
							}
						}, TaskCreationOptions.LongRunning);
				}

				// Ready? Set() Go!
				sync.Set();
				Task.WaitAll(tasks);
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