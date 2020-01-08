using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Tests
{
	using Extensions;
	using Hash;
	using Mac;

	// https://github.com/dotnet/corefx/blob/65396180809600fc7f610cb869dfbfa1d9d10b55/src/System.Security.Cryptography.Algorithms/tests/HmacTests.cs

	internal static class ByteUtils
	{
		internal static byte[] AsciiBytes(string s) => Utils.SafeUTF8.GetBytes(s);
		internal static byte[] HexToByteArray(this string hexString) => hexString.FromBase16();
		internal static string ByteArrayToHex(this byte[] bytes) => bytes.ToBase16();

		internal static byte[] RepeatByte(byte b, int count)
		{
			byte[] value = new byte[count];
			for (int i = 0; i < count; i++) value[i] = b;
			return value;
		}
	}

	public abstract class HmacTests
	{
		// RFC2202 defines the test vectors for HMACMD5 and HMACSHA1
		// RFC4231 defines the test vectors for HMACSHA{224,256,384,512}
		// They share the same datasets for cases 1-5, but cases 6 and 7 differ.
		private readonly byte[][] _testKeys;
		private readonly byte[][] _testData;

		protected HmacTests(byte[][] testKeys, byte[][] testData)
		{
			_testKeys = testKeys;
			_testData = testData;
		}

		protected abstract HMAC Create();

		protected abstract HashAlgorithm CreateHashAlgorithm();

		protected abstract int BlockSize { get; }

		protected void VerifyHmac(
			int testCaseId,
			string digest,
			int truncateSize = -1)
		{
			byte[] digestBytes = digest.FromBase16();
			byte[] computedDigest;

			using (HMAC hmac = Create())
			{
				Assert.IsTrue(hmac.HashSize > 0);

				byte[] key = (byte[])_testKeys[testCaseId].Clone();
				hmac.Key = key;

				// make sure the getter returns different objects each time
				Assert.AreNotSame(key, hmac.Key);
				Assert.AreNotSame(hmac.Key, hmac.Key);

				// make sure the setter didn't cache the exact object we passed in
				key[0] = (byte)(key[0] + 1);
				Assert.IsFalse(Enumerable.SequenceEqual(key, hmac.Key));

				computedDigest = hmac.ComputeHash(_testData[testCaseId]);
			}

			if (truncateSize != -1)
			{
				byte[] tmp = new byte[truncateSize];
				Array.Copy(computedDigest, 0, tmp, 0, truncateSize);
				computedDigest = tmp;
			}

			Assert.IsTrue(Enumerable.SequenceEqual(digestBytes, computedDigest));
		}

		protected void VerifyHmacRfc2104_2()
		{
			// Ensure that keys shorter than the threshold don't get altered.
			using (HMAC hmac = Create())
			{
				byte[] key = new byte[BlockSize];
				hmac.Key = key;
				byte[] retrievedKey = hmac.Key;
				Assert.IsTrue(Enumerable.SequenceEqual(key, retrievedKey));
			}

			// Ensure that keys longer than the threshold are adjusted via Rfc2104 Section 2.
			using (HMAC hmac = Create())
			{
				byte[] overSizedKey = new byte[BlockSize + 1];
				hmac.Key = overSizedKey;
				byte[] actualKey = hmac.Key;
				byte[] expectedKey = CreateHashAlgorithm().ComputeHash(overSizedKey);
				Assert.IsTrue(Enumerable.SequenceEqual(expectedKey, actualKey));

				// Also ensure that the hashing operation uses the adjusted key.
				byte[] data = new byte[100];
				hmac.Key = expectedKey;
				byte[] expectedHash = hmac.ComputeHash(data);

				hmac.Key = overSizedKey;
				byte[] actualHash = hmac.ComputeHash(data);
				Assert.IsTrue(Enumerable.SequenceEqual(expectedHash, actualHash));
			}
		}
	}//class HmacTests

	public abstract class Rfc2202HmacTests : HmacTests
	{
		private static readonly byte[][] s_testData2202 =
		{
			null,
			ByteUtils.AsciiBytes("Hi There"),
			ByteUtils.AsciiBytes("what do ya want for nothing?"),
			ByteUtils.RepeatByte(0xdd, 50),
			ByteUtils.RepeatByte(0xcd, 50),
			ByteUtils.AsciiBytes("Test With Truncation"),
			ByteUtils.AsciiBytes("Test Using Larger Than Block-Size Key - Hash Key First"),
			ByteUtils.AsciiBytes("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"),
		};

		// The keys for test cases 1, 3, and 5 for RFC2202 are sized to match the
		// algorithm (16 bytes for MD5, 20 for SHA-1), so they need to be provided by
		// the more derived type.
		protected Rfc2202HmacTests(byte[][] testKeys) :
			base(testKeys, s_testData2202)
		{
		}
	}//class Rfc2202HmacTests

	public abstract class Rfc4231HmacTests : HmacTests
	{
		private static readonly byte[][] s_testKeys4231 =
		{
			null,
			ByteUtils.RepeatByte(0x0b, 20),
			ByteUtils.AsciiBytes("Jefe"),
			ByteUtils.RepeatByte(0xaa, 20),
			ByteUtils.HexToByteArray("0102030405060708090a0b0c0d0e0f10111213141516171819"),
			ByteUtils.HexToByteArray("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
			ByteUtils.RepeatByte(0xaa, 131),
			ByteUtils.RepeatByte(0xaa, 131),
		};

		private static readonly byte[][] s_testData4231 =
		{
			null,
			ByteUtils.AsciiBytes("Hi There"),
			ByteUtils.AsciiBytes("what do ya want for nothing?"),
			ByteUtils.RepeatByte(0xdd, 50),
			ByteUtils.RepeatByte(0xcd, 50),
			ByteUtils.AsciiBytes("Test With Truncation"),
			ByteUtils.AsciiBytes("Test Using Larger Than Block-Size Key - Hash Key First"),
			ByteUtils.AsciiBytes("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
		};

		protected Rfc4231HmacTests() :
			base(s_testKeys4231, s_testData4231)
		{
		}
	}//class Rfc4231HmacTests 

	[TestClass]
	public class HmacSha1Tests : Rfc2202HmacTests
	{
		private static readonly byte[][] s_testKeys2202 =
		{
			null,
			ByteUtils.RepeatByte(0x0b, 20),
			ByteUtils.AsciiBytes("Jefe"),
			ByteUtils.RepeatByte(0xaa, 20),
			ByteUtils.HexToByteArray("0102030405060708090a0b0c0d0e0f10111213141516171819"),
			ByteUtils.RepeatByte(0x0c, 20),
			ByteUtils.RepeatByte(0xaa, 80),
			ByteUtils.RepeatByte(0xaa, 80),
		};

		public HmacSha1Tests()
			: base(s_testKeys2202)
		{
		}

		protected override HMAC Create()
		{
			return new HMAC2(HashFactories.SHA1);
		}

		protected override HashAlgorithm CreateHashAlgorithm()
		{
#if NET462
			return new SHA1Cng();
#else
			return SHA1.Create();
#endif
		}

		protected override int BlockSize { get { return 64; } }

		[TestMethod]
		public void HmacSha1_Rfc2202_1()
		{
			VerifyHmac(1, "b617318655057264e28bc0b6fb378c8ef146be00");
		}

		[TestMethod]
		public void HmacSha1_Rfc2202_2()
		{
			VerifyHmac(2, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
		}

		[TestMethod]
		public void HmacSha1_Rfc2202_3()
		{
			VerifyHmac(3, "125d7342b9ac11cd91a39af48aa17b4f63f175d3");
		}

		[TestMethod]
		public void HmacSha1_Rfc2202_4()
		{
			VerifyHmac(4, "4c9007f4026250c6bc8414f9bf50c86c2d7235da");
		}

		[TestMethod]
		public void HmacSha1_Rfc2202_5()
		{
			VerifyHmac(5, "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04");
		}

		[TestMethod]
		public void HmacSha1_Rfc2202_6()
		{
			VerifyHmac(6, "aa4ae5e15272d00e95705637ce8a3b55ed402112");
		}

		[TestMethod]
		public void HmacSha1_Rfc2202_7()
		{
			VerifyHmac(7, "e8e99d0f45237d786d6bbaa7965c7808bbff1a91");
		}

		[TestMethod]
		public void HMacSha1_Rfc2104_2()
		{
			VerifyHmacRfc2104_2();
		}
	}//class HmacSha1Tests

	[TestClass]
	public class HmacSha256Tests : Rfc4231HmacTests
	{
		protected override HMAC Create()
		{
			return new HMAC2(HashFactories.SHA256);
		}

		protected override HashAlgorithm CreateHashAlgorithm()
		{
#if NET462
			return new SHA256Cng();
#else
			return SHA256.Create();
#endif
		}

		protected override int BlockSize { get { return 64; } }

		[TestMethod]
		public void HmacSha256_Rfc4231_1()
		{
			VerifyHmac(1, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
		}

		[TestMethod]
		public void HmacSha256_Rfc4231_2()
		{
			VerifyHmac(2, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
		}

		[TestMethod]
		public void HmacSha256_Rfc4231_3()
		{
			VerifyHmac(3, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
		}

		[TestMethod]
		public void HmacSha256_Rfc4231_4()
		{
			VerifyHmac(4, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
		}

		[TestMethod]
		public void HmacSha256_Rfc4231_5()
		{
			// RFC 4231 only defines the first 128 bits of this value.
			VerifyHmac(5, "a3b6167473100ee06e0c796c2955552b", 128 / 8);
		}

		[TestMethod]
		public void HmacSha256_Rfc4231_6()
		{
			VerifyHmac(6, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
		}

		[TestMethod]
		public void HmacSha256_Rfc4231_7()
		{
			VerifyHmac(7, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
		}

		[TestMethod]
		public void HMacSha256_Rfc2104_2()
		{
			VerifyHmacRfc2104_2();
		}
	}//class HmacSha256Tests

	[TestClass]
	public class HmacSha384Tests : Rfc4231HmacTests
	{
		protected override HMAC Create()
		{
			return new HMAC2(HashFactories.SHA384);
		}

		protected override HashAlgorithm CreateHashAlgorithm()
		{
#if NET462
			return new SHA384Cng();
#else
			return SHA384.Create();
#endif
		}

		protected override int BlockSize { get { return 128; } }

		[TestMethod]
		public void HmacSha384_Rfc4231_1()
		{
			VerifyHmac(1, "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
		}

		[TestMethod]
		public void HmacSha384_Rfc4231_2()
		{
			VerifyHmac(2, "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649");
		}

		[TestMethod]
		public void HmacSha384_Rfc4231_3()
		{
			VerifyHmac(3, "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27");
		}

		[TestMethod]
		public void HmacSha384_Rfc4231_4()
		{
			VerifyHmac(4, "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb");
		}

		[TestMethod]
		public void HmacSha384_Rfc4231_5()
		{
			// RFC 4231 only defines the first 128 bits of this value.
			VerifyHmac(5, "3abf34c3503b2a23a46efc619baef897", 128 / 8);
		}

		[TestMethod]
		public void HmacSha384_Rfc4231_6()
		{
			VerifyHmac(6, "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952");
		}

		[TestMethod]
		public void HmacSha384_Rfc4231_7()
		{
			VerifyHmac(7, "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e");
		}

		[TestMethod]
		public void HMacSha384_Rfc2104_2()
		{
			VerifyHmacRfc2104_2();
		}
	}//class HmacSha384Tests

	[TestClass]
	public class HmacSha512Tests : Rfc4231HmacTests
	{
		protected override HMAC Create()
		{
			return new HMAC2(HashFactories.SHA512);
		}

		protected override HashAlgorithm CreateHashAlgorithm()
		{
#if NET462
			return new SHA512Cng();
#else
			return SHA512.Create();
#endif
		}

		protected override int BlockSize { get { return 128; } }

		[TestMethod]
		public void HmacSha512_Rfc4231_1()
		{
			VerifyHmac(1, "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
		}

		[TestMethod]
		public void HmacSha512_Rfc4231_2()
		{
			VerifyHmac(2, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
		}

		[TestMethod]
		public void HmacSha512_Rfc4231_3()
		{
			VerifyHmac(3, "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
		}

		[TestMethod]
		public void HmacSha512_Rfc4231_4()
		{
			VerifyHmac(4, "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");
		}

		[TestMethod]
		public void HmacSha512_Rfc4231_5()
		{
			// RFC 4231 only defines the first 128 bits of this value.
			VerifyHmac(5, "415fad6271580a531d4179bc891d87a6", 128 / 8);
		}

		[TestMethod]
		public void HmacSha512_Rfc4231_6()
		{
			VerifyHmac(6, "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");
		}

		[TestMethod]
		public void HmacSha512_Rfc4231_7()
		{
			VerifyHmac(7, "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");
		}

		[TestMethod]
		public void HMacSha512_Rfc2104_2()
		{
			VerifyHmacRfc2104_2();
		}
	}// class HmacSha512Tests

	[TestClass]
	public class ReusabilityTests
	{
		[TestMethod]
		public void HMAC_ReusabilityTests()
		{
			var hmacFactories = new Func<HMAC>[] { HMACFactories.HMACSHA1, HMACFactories.HMACSHA256, HMACFactories.HMACSHA384, HMACFactories.HMACSHA512 };
			byte[] input = { 8, 6, 7, 5, 3, 0, 9, };

			foreach (var hmacFactory in hmacFactories)
			{
				using (var hashAlgorithm = hmacFactory())
				{
					byte[] hash1 = hashAlgorithm.ComputeHash(input);
					byte[] hash2 = hashAlgorithm.ComputeHash(input);

					Assert.IsTrue(Enumerable.SequenceEqual(hash1, hash2));
				}
			}
		}// HMAC_ReusabilityTests()
	}// class HMAC_ReusabilityTests
}//ns