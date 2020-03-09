using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityDriven.Inferno.Tests
{
	using Extensions;
	using Hash;
	using Kdf;
	using Mac;

	[TestClass]
	public class _Sanity_Test
	{

		[TestMethod]
		public void _Sanity()
		{
			Assembly assembly = typeof(SecurityDriven.Inferno.CryptoRandom).Assembly;
			FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
			const string expectedVersion = "1.6.2.0";

			Assert.IsTrue(fvi.ProductVersion == expectedVersion);
			Assert.IsTrue(fvi.FileVersion == expectedVersion);

			assembly.GetModules()[0].GetPEKind(out var kind, out var machine);
			Assert.IsTrue(kind == PortableExecutableKinds.ILOnly);

			string environment =
#if NET462
				"[.NET 4.6.2] " + Environment.Version;
#elif NETCOREAPP2_1
				"[CORE 2.1] " + Environment.Version + "\nFrom: " + System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();

#elif NETSTANDARD
				"[NETSTANDARD] " + Environment.Version + "\nFrom: " + System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
#endif
			Console.WriteLine(environment);
		}
	}// class Sanity_Test

	//http://tools.ietf.org/html/rfc4231
	[TestClass]
	public class HMAC2_Test
	{
		byte[] key, data;
		byte[] result_256, result_384, result_512;
		byte[] expected_256, expected_384, expected_512;

		[TestMethod]
		public void HMAC2_Testcase1()
		{
			key = Enumerable.Repeat<byte>(0x0b, 20).ToArray();
			data = Encoding.ASCII.GetBytes("Hi There");

			result_256 = new HMAC2(HashFactories.SHA256, key).ComputeHash(data);
			result_384 = new HMAC2(HashFactories.SHA384, key).ComputeHash(data);
			result_512 = new HMAC2(HashFactories.SHA512, key).ComputeHash(data);

			expected_256 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7".FromBase16();
			expected_384 = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6".FromBase16();
			expected_512 = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854".FromBase16();

			Assert.IsTrue(Enumerable.SequenceEqual(result_256, expected_256));
			Assert.IsTrue(Enumerable.SequenceEqual(result_384, expected_384));
			Assert.IsTrue(Enumerable.SequenceEqual(result_512, expected_512));
		}

		[TestMethod]
		public void HMAC2_Testcase2()
		{
			key = Encoding.ASCII.GetBytes("Jefe");
			data = Encoding.ASCII.GetBytes("what do ya want for nothing?");

			result_256 = new HMAC2(HashFactories.SHA256, key).ComputeHash(data);
			result_384 = new HMAC2(HashFactories.SHA384, key).ComputeHash(data);
			result_512 = new HMAC2(HashFactories.SHA512, key).ComputeHash(data);

			expected_256 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843".FromBase16();
			expected_384 = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649".FromBase16();
			expected_512 = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737".FromBase16();

			Assert.IsTrue(Enumerable.SequenceEqual(result_256, expected_256));
			Assert.IsTrue(Enumerable.SequenceEqual(result_384, expected_384));
			Assert.IsTrue(Enumerable.SequenceEqual(result_512, expected_512));
		}

		[TestMethod]
		public void HMAC2_Testcase3()
		{
			key = Enumerable.Repeat<byte>(0xaa, 20).ToArray();
			data = Enumerable.Repeat<byte>(0xdd, 50).ToArray();

			result_256 = new HMAC2(HashFactories.SHA256, key).ComputeHash(data);
			result_384 = new HMAC2(HashFactories.SHA384, key).ComputeHash(data);
			result_512 = new HMAC2(HashFactories.SHA512, key).ComputeHash(data);

			expected_256 = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe".FromBase16();
			expected_384 = "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27".FromBase16();
			expected_512 = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb".FromBase16();

			Assert.IsTrue(Enumerable.SequenceEqual(result_256, expected_256));
			Assert.IsTrue(Enumerable.SequenceEqual(result_384, expected_384));
			Assert.IsTrue(Enumerable.SequenceEqual(result_512, expected_512));
		}

		[TestMethod]
		public void HMAC2_Testcase4()
		{
			key = Enumerable.Range(1, 25).Select(i => (byte)i).ToArray();
			data = Enumerable.Repeat<byte>(0xcd, 50).ToArray();

			result_256 = new HMAC2(HashFactories.SHA256, key).ComputeHash(data);
			result_384 = new HMAC2(HashFactories.SHA384, key).ComputeHash(data);
			result_512 = new HMAC2(HashFactories.SHA512, key).ComputeHash(data);

			expected_256 = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b".FromBase16();
			expected_384 = "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb".FromBase16();
			expected_512 = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd".FromBase16();

			Assert.IsTrue(Enumerable.SequenceEqual(result_256, expected_256));
			Assert.IsTrue(Enumerable.SequenceEqual(result_384, expected_384));
			Assert.IsTrue(Enumerable.SequenceEqual(result_512, expected_512));
		}

		//Test with a truncation of output to 128 bits.
		[TestMethod]
		public void HMAC2_Testcase5()
		{
			key = Enumerable.Repeat<byte>(0x0c, 20).ToArray();
			data = Encoding.ASCII.GetBytes("Test With Truncation");

			result_256 = new HMAC2(HashFactories.SHA256, key).ComputeHash(data).Take(16).ToArray();
			result_384 = new HMAC2(HashFactories.SHA384, key).ComputeHash(data).Take(16).ToArray();
			result_512 = new HMAC2(HashFactories.SHA512, key).ComputeHash(data).Take(16).ToArray();

			expected_256 = "a3b6167473100ee06e0c796c2955552b".FromBase16();
			expected_384 = "3abf34c3503b2a23a46efc619baef897".FromBase16();
			expected_512 = "415fad6271580a531d4179bc891d87a6".FromBase16();

			Assert.IsTrue(Enumerable.SequenceEqual(result_256, expected_256));
			Assert.IsTrue(Enumerable.SequenceEqual(result_384, expected_384));
			Assert.IsTrue(Enumerable.SequenceEqual(result_512, expected_512));
		}

		[TestMethod]
		public void HMAC2_Testcase6()
		{
			key = Enumerable.Repeat<byte>(0xaa, 131).ToArray();
			data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");

			result_256 = new HMAC2(HashFactories.SHA256, key).ComputeHash(data);
			result_384 = new HMAC2(HashFactories.SHA384, key).ComputeHash(data);
			result_512 = new HMAC2(HashFactories.SHA512, key).ComputeHash(data);

			expected_256 = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54".FromBase16();
			expected_384 = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952".FromBase16();
			expected_512 = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598".FromBase16();

			Assert.IsTrue(Enumerable.SequenceEqual(result_256, expected_256));
			Assert.IsTrue(Enumerable.SequenceEqual(result_384, expected_384));
			Assert.IsTrue(Enumerable.SequenceEqual(result_512, expected_512));
		}

		[TestMethod]
		public void HMAC2_Testcase7()
		{
			key = Enumerable.Repeat<byte>(0xaa, 131).ToArray();
			data = Encoding.ASCII.GetBytes("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");

			result_256 = new HMAC2(HashFactories.SHA256, key).ComputeHash(data);
			result_384 = new HMAC2(HashFactories.SHA384, key).ComputeHash(data);
			result_512 = new HMAC2(HashFactories.SHA512, key).ComputeHash(data);

			expected_256 = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2".FromBase16();
			expected_384 = "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e".FromBase16();
			expected_512 = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58".FromBase16();

			Assert.IsTrue(Enumerable.SequenceEqual(result_256, expected_256));
			Assert.IsTrue(Enumerable.SequenceEqual(result_384, expected_384));
			Assert.IsTrue(Enumerable.SequenceEqual(result_512, expected_512));
		}

	}//class HMAC2_Test

	[TestClass]
	public class PBKDF2_Test
	{
		public PBKDF2_Test()
		{
		}

		//https://www.ietf.org/rfc/rfc6070.txt (PBKDF2 SHA1 test vectors)
		[TestMethod]
		public void PBKDF2_SHA1()
		{
			// tests with salt less than 8 bytes are skipped since our implementation throws on such weak salts.
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA1(), HMACFactories.HMACSHA1 };
			foreach (var hmacFactory in hmacFactories)
			{
				var result = new PBKDF2(hmacFactory,
					password: Encoding.ASCII.GetBytes("passwordPASSWORDpassword"),
					salt: Encoding.ASCII.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
					iterations: 4096).GetBytes(25);

				var expected = "3d 2e ec 4f e4 1c 84 9b 80 c8 d8 36 62 c0 e4 4a 8b 29 1a 96 4c f2 f0 70 38".Replace(" ", "").FromBase16();
				Assert.IsTrue(Enumerable.SequenceEqual(expected, result));
			}
		}

		//http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors (PBKDF2 SHA256 test vectors)
		[TestMethod]
		public void PBKDF2_SHA256()
		{
			// tests with salt less than 8 bytes are skipped since our implementation throws on such weak salts.
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA256(), HMACFactories.HMACSHA256 };
			foreach (var hmacFactory in hmacFactories)
			{
				var result = new PBKDF2(hmacFactory,
					password: Encoding.ASCII.GetBytes("passwordPASSWORDpassword"),
					salt: Encoding.ASCII.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
					iterations: 4096).GetBytes(40);

				var expected = "34 8c 89 db cb d3 2b 2f 32 d8 14 b8 11 6e 84 cf 2b 17 34 7e bc 18 00 18 1c 4e 2a 1f b8 dd 53 e1 c6 35 51 8c 7d ac 47 e9".Replace(" ", "").FromBase16();
				Assert.IsTrue(Enumerable.SequenceEqual(expected, result));

				result = new PBKDF2(hmacFactory,
					password: Encoding.ASCII.GetBytes("passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04Uz3ebEAhzZ4ve1A2wg5CnLXdZC5Y7gwfVgbEgZSTmoYQSzC5OW4dfrjqiwApTACO6xoOL1AjWj6X6f6qFfF8TVmOzU9RhOd1N4QtzWI4fP6FYttNz5FuLdtYVXWVXH2Tf7I9fieMeWCHTMkM4VcmQyQHpbcP8MEb5f1g6Ckg5xk3HQr3wMBvQcOHpCPy1K8HCM7a5wkPDhgVA0BVmwNpsRIbDQZRtHK6dT6bGyalp6gbFZBuBHwD86gTzkrFY7HkOVrgc0gJcGJZe65Ce8v4Jn5OzkuVsiU8efm2Pw2RnbpWSAr7SkVdCwXK2XSJDQ5fZ4HBEz9VTFYrG23ELuLjvx5njOLNgDAJuf5JB2tn4nMjjcnl1e8qcYVwZqFzEv2zhLyDWMkV4tzl4asLnvyAxTBkxPRZj2pRABWwb3kEofpsHYxMTAn38YSpZreoXipZWBnu6HDURaruXaIPYFPYHl9Ls9wsuD7rzaGfbOyfVgLIGK5rODphwRA7lm88bGKY8b7tWOtepyEvaLxMI7GZF5ScwpZTYeEDNUKPzvM2Im9zehIaznpguNdNXNMLWnwPu4H6zEvajkw3G3ucSiXKmh6XNe3hkdSANm3vnxzRXm4fcuzAx68IElXE2bkGFElluDLo6EsUDWZ4JIWBVaDwYdJx8uCXbQdoifzCs5kuuClaDaDqIhb5hJ2WR8mxiueFsS0aDGdIYmye5svmNmzQxFmdOkHoF7CfwuU1yy4uEEt9vPSP2wFp1dyaMvJW68vtB4kddLmI6gIgVVcT6ZX1Qm6WsusPrdisPLB2ScodXojCbL3DLj6PKG8QDVMWTrL1TpafT2wslRledWIhsTlv2mI3C066WMcTSwKLXdEDhVvFJ6ShiLKSN7gnRrlE0BnAw"),
					salt: Encoding.ASCII.GetBytes("saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6PlBdILBOkKUB6TGTPJXh1tpdOHTG6KuIvcbQp9qWjaf1uxAKgiTtYRIHhxjJI2viVa6fDZ67QOouOaf2RXQhpsWaTtAVnff6PIFcvJhdPDFGV5nvmZWoCZQodj6yXRDHPw9PyF0iLYm9uFtEunlAAxGB5qqea4X5tZvB1OfLVwymY3a3JPjdxTdvHxCHbqqE0zip61JNqdmeWxGtlRBC6CGoCiHO4XxHCntQBRJDcG0zW7joTdgtTBarsQQhlLXBGMNBSNmmTbDf3hFtawUBCJH18IAiRMwyeQJbJ2bERsY3MVRPuYCf4Au7gN72iGh1lRktSQtEFye7pO46kMXRrEjHQWXInMzzy7X2StXUzHVTFF2VdOoKn0WUqFNvB6PF7qIsOlYKj57bi1Psa34s85WxMSbTkhrd7VHdHZkTVaWdraohXYOePdeEvIwObCGEXkETUzqM5P2yzoBOJSdjpIYaa8zzdLD3yrb1TwCZuJVxsrq0XXY6vErU4QntsW0972XmGNyumFNJiPm4ONKh1RLvS1kddY3nm8276S4TUuZfrRQO8QxZRNuSaZI8JRZp5VojB5DktuMxAQkqoPjQ5Vtb6oXeOyY591CB1MEW1fLTCs0NrL321SaNRMqza1ETogAxpEiYwZ6pIgnMmSqNMRdZnCqA4gMWw1lIVATWK83OCeicNRUNOdfzS7A8vbLcmvKPtpOFvhNzwrrUdkvuKvaYJviQgeR7snGetO9JLCwIlHIj52gMCNU18d32SJl7Xomtl3wIe02SMvq1i1BcaX7lXioqWGmgVqBWU3fsUuGwHi6RUKCCQdEOBfNo2WdpFaCflcgnn0O6jVHCqkv8cQk81AqS00rAmHGCNTwyA6Tq5TXoLlDnC8gAQjDUsZp0z"),
					iterations: 100000).GetBytes(32 + 1);

				expected = "25BC2936281DB8D43C6D612B1C6F7A137EC53E0F45777252401813D5AB6C7A0EF8".FromBase16();
				Assert.IsTrue(Enumerable.SequenceEqual(expected, result));
			}
		}

		//https://github.com/Anti-weakpasswords/PBKDF2-Test-Vectors/releases/tag/1.0
		[TestMethod]
		public void PBKDF2_SHA384()
		{
			byte[] result, expected;
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA384(), HMACFactories.HMACSHA384 };
			foreach (var hmacFactory in hmacFactories)
			{
				result = new PBKDF2(hmacFactory,
					password: Encoding.ASCII.GetBytes("passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqK"),
					salt: Encoding.ASCII.GetBytes("saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcG"),
					iterations: 1).GetBytes(48);

				expected = "0644A3489B088AD85A0E42BE3E7F82500EC18936699151A2C90497151BAC7BB69300386A5E798795BE3CEF0A3C803227".FromBase16();
				Assert.IsTrue(Enumerable.SequenceEqual(expected, result));

				result = new PBKDF2(hmacFactory,
						password: Encoding.ASCII.GetBytes("passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04Uz3ebEAhzZ4ve1A2wg5CnLXdZC5Y7gwfVgbEgZSTmoYQSzC5OW4dfrjqiwApTACO6xoOL1AjWj6X6f6qFfF8TVmOzU9RhOd1N4QtzWI4fP6FYttNz5FuLdtYVXWVXH2Tf7I9fieMeWCHTMkM4VcmQyQHpbcP8MEb5f1g6Ckg5xk3HQr3wMBvQcOHpCPy1K8HCM7a5wkPDhgVA0BVmwNpsRIbDQZRtHK6dT6bGyalp6gbFZBuBHwD86gTzkrFY7HkOVrgc0gJcGJZe65Ce8v4Jn5OzkuVsiU8efm2Pw2RnbpWSAr7SkVdCwXK2XSJDQ5fZ4HBEz9VTFYrG23ELuLjvx5njOLNgDAJuf5JB2tn4nMjjcnl1e8qcYVwZqFzEv2zhLyDWMkV4tzl4asLnvyAxTBkxPRZj2pRABWwb3kEofpsHYxMTAn38YSpZreoXipZWBnu6HDURaruXaIPYFPYHl9Ls9wsuD7rzaGfbOyfVgLIGK5rODphwRA7lm88bGKY8b7tWOtepyEvaLxMI7GZF5ScwpZTYeEDNUKPzvM2Im9zehIaznpguNdNXNMLWnwPu4H6zEvajkw3G3ucSiXKmh6XNe3hkdSANm3vnxzRXm4fcuzAx68IElXE2bkGFElluDLo6EsUDWZ4JIWBVaDwYdJx8uCXbQdoifzCs5kuuClaDaDqIhb5hJ2WR8mxiueFsS0aDGdIYmye5svmNmzQxFmdOkHoF7CfwuU1yy4uEEt9vPSP2wFp1dyaMvJW68vtB4kddLmI6gIgVVcT6ZX1Qm6WsusPrdisPLB2ScodXojCbL3DLj6PKG8QDVMWTrL1TpafT2wslRledWIhsTlv2mI3C066WMcTSwKLXdEDhVvFJ6ShiLKSN7gnRrlE0BnAw"),
						salt: Encoding.ASCII.GetBytes("saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6PlBdILBOkKUB6TGTPJXh1tpdOHTG6KuIvcbQp9qWjaf1uxAKgiTtYRIHhxjJI2viVa6fDZ67QOouOaf2RXQhpsWaTtAVnff6PIFcvJhdPDFGV5nvmZWoCZQodj6yXRDHPw9PyF0iLYm9uFtEunlAAxGB5qqea4X5tZvB1OfLVwymY3a3JPjdxTdvHxCHbqqE0zip61JNqdmeWxGtlRBC6CGoCiHO4XxHCntQBRJDcG0zW7joTdgtTBarsQQhlLXBGMNBSNmmTbDf3hFtawUBCJH18IAiRMwyeQJbJ2bERsY3MVRPuYCf4Au7gN72iGh1lRktSQtEFye7pO46kMXRrEjHQWXInMzzy7X2StXUzHVTFF2VdOoKn0WUqFNvB6PF7qIsOlYKj57bi1Psa34s85WxMSbTkhrd7VHdHZkTVaWdraohXYOePdeEvIwObCGEXkETUzqM5P2yzoBOJSdjpIYaa8zzdLD3yrb1TwCZuJVxsrq0XXY6vErU4QntsW0972XmGNyumFNJiPm4ONKh1RLvS1kddY3nm8276S4TUuZfrRQO8QxZRNuSaZI8JRZp5VojB5DktuMxAQkqoPjQ5Vtb6oXeOyY591CB1MEW1fLTCs0NrL321SaNRMqza1ETogAxpEiYwZ6pIgnMmSqNMRdZnCqA4gMWw1lIVATWK83OCeicNRUNOdfzS7A8vbLcmvKPtpOFvhNzwrrUdkvuKvaYJviQgeR7snGetO9JLCwIlHIj52gMCNU18d32SJl7Xomtl3wIe02SMvq1i1BcaX7lXioqWGmgVqBWU3fsUuGwHi6RUKCCQdEOBfNo2WdpFaCflcgnn0O6jVHCqkv8cQk81AqS00rAmHGCNTwyA6Tq5TXoLlDnC8gAQjDUsZp0z"),
						iterations: 100000).GetBytes(48 + 1);

				expected = "7BADBDA9DBE9D5AB9237268D57ABB235B6B729AEFA9CACDF5E3007136F1178231FCFFE3E6437D9EF713EC32887C4B42674".FromBase16();
				Assert.IsTrue(Enumerable.SequenceEqual(expected, result));
			}
		}

		//http://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors (PBKDF2 SHA512 test vectors)
		[TestMethod]
		public void PBKDF2_SHA512()
		{
			// tests with salt less than 8 bytes are skipped since our implementation throws on such weak salts.
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA512(), HMACFactories.HMACSHA512 };
			foreach (var hmacFactory in hmacFactories)
			{
				var result = new PBKDF2(hmacFactory,
					password: Encoding.ASCII.GetBytes("passwordPASSWORDpassword"),
					salt: Encoding.ASCII.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
					iterations: 4096).GetBytes(64);

				var expected = "8c 05 11 f4 c6 e5 97 c6 ac 63 15 d8 f0 36 2e 22 5f 3c 50 14 95 ba 23 b8 68 c0 05 17 4d c4 ee 71 11 5b 59 f9 e6 0c d9 53 2f a3 3e 0f 75 ae fe 30 22 5c 58 3a 18 6c d8 2b d4 da ea 97 24 a3 d3 b8".Replace(" ", "").FromBase16();
				Assert.IsTrue(Enumerable.SequenceEqual(expected, result));

				result = new PBKDF2(hmacFactory,
						password: Encoding.ASCII.GetBytes("passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04Uz3ebEAhzZ4ve1A2wg5CnLXdZC5Y7gwfVgbEgZSTmoYQSzC5OW4dfrjqiwApTACO6xoOL1AjWj6X6f6qFfF8TVmOzU9RhOd1N4QtzWI4fP6FYttNz5FuLdtYVXWVXH2Tf7I9fieMeWCHTMkM4VcmQyQHpbcP8MEb5f1g6Ckg5xk3HQr3wMBvQcOHpCPy1K8HCM7a5wkPDhgVA0BVmwNpsRIbDQZRtHK6dT6bGyalp6gbFZBuBHwD86gTzkrFY7HkOVrgc0gJcGJZe65Ce8v4Jn5OzkuVsiU8efm2Pw2RnbpWSAr7SkVdCwXK2XSJDQ5fZ4HBEz9VTFYrG23ELuLjvx5njOLNgDAJuf5JB2tn4nMjjcnl1e8qcYVwZqFzEv2zhLyDWMkV4tzl4asLnvyAxTBkxPRZj2pRABWwb3kEofpsHYxMTAn38YSpZreoXipZWBnu6HDURaruXaIPYFPYHl9Ls9wsuD7rzaGfbOyfVgLIGK5rODphwRA7lm88bGKY8b7tWOtepyEvaLxMI7GZF5ScwpZTYeEDNUKPzvM2Im9zehIaznpguNdNXNMLWnwPu4H6zEvajkw3G3ucSiXKmh6XNe3hkdSANm3vnxzRXm4fcuzAx68IElXE2bkGFElluDLo6EsUDWZ4JIWBVaDwYdJx8uCXbQdoifzCs5kuuClaDaDqIhb5hJ2WR8mxiueFsS0aDGdIYmye5svmNmzQxFmdOkHoF7CfwuU1yy4uEEt9vPSP2wFp1dyaMvJW68vtB4kddLmI6gIgVVcT6ZX1Qm6WsusPrdisPLB2ScodXojCbL3DLj6PKG8QDVMWTrL1TpafT2wslRledWIhsTlv2mI3C066WMcTSwKLXdEDhVvFJ6ShiLKSN7gnRrlE0BnAw"),
						salt: Encoding.ASCII.GetBytes("saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6PlBdILBOkKUB6TGTPJXh1tpdOHTG6KuIvcbQp9qWjaf1uxAKgiTtYRIHhxjJI2viVa6fDZ67QOouOaf2RXQhpsWaTtAVnff6PIFcvJhdPDFGV5nvmZWoCZQodj6yXRDHPw9PyF0iLYm9uFtEunlAAxGB5qqea4X5tZvB1OfLVwymY3a3JPjdxTdvHxCHbqqE0zip61JNqdmeWxGtlRBC6CGoCiHO4XxHCntQBRJDcG0zW7joTdgtTBarsQQhlLXBGMNBSNmmTbDf3hFtawUBCJH18IAiRMwyeQJbJ2bERsY3MVRPuYCf4Au7gN72iGh1lRktSQtEFye7pO46kMXRrEjHQWXInMzzy7X2StXUzHVTFF2VdOoKn0WUqFNvB6PF7qIsOlYKj57bi1Psa34s85WxMSbTkhrd7VHdHZkTVaWdraohXYOePdeEvIwObCGEXkETUzqM5P2yzoBOJSdjpIYaa8zzdLD3yrb1TwCZuJVxsrq0XXY6vErU4QntsW0972XmGNyumFNJiPm4ONKh1RLvS1kddY3nm8276S4TUuZfrRQO8QxZRNuSaZI8JRZp5VojB5DktuMxAQkqoPjQ5Vtb6oXeOyY591CB1MEW1fLTCs0NrL321SaNRMqza1ETogAxpEiYwZ6pIgnMmSqNMRdZnCqA4gMWw1lIVATWK83OCeicNRUNOdfzS7A8vbLcmvKPtpOFvhNzwrrUdkvuKvaYJviQgeR7snGetO9JLCwIlHIj52gMCNU18d32SJl7Xomtl3wIe02SMvq1i1BcaX7lXioqWGmgVqBWU3fsUuGwHi6RUKCCQdEOBfNo2WdpFaCflcgnn0O6jVHCqkv8cQk81AqS00rAmHGCNTwyA6Tq5TXoLlDnC8gAQjDUsZp0z"),
						iterations: 100000).GetBytes(64 + 1);

				expected = "B8674F6C0CC9F8CF1F1874534FD5AF01FC1504D76C2BC2AA0A75FE4DD5DFD1DAF60EA7C85F122BCEEB8772659D601231607726998EAC3F6AAB72EFF7BA349F7FD7".FromBase16();
				Assert.IsTrue(Enumerable.SequenceEqual(expected, result));
			}
		}
	}//class PBKDF2_Test

	//http://tools.ietf.org/html/rfc4648#section-10
	[TestClass]
	public class Base32_and_Base16_Test
	{
		//from: https://github.com/CodesInChaos/Chaos.NaCl/blob/master/Chaos.NaCl.Tests/CryptoBytesTest.cs
		static readonly byte[] test_bytes = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

		const string HexStringUpper =
			"000102030405060708090A0B0C0D0E0F" +
			"101112131415161718191A1B1C1D1E1F" +
			"202122232425262728292A2B2C2D2E2F" +
			"303132333435363738393A3B3C3D3E3F" +
			"404142434445464748494A4B4C4D4E4F" +
			"505152535455565758595A5B5C5D5E5F" +
			"606162636465666768696A6B6C6D6E6F" +
			"707172737475767778797A7B7C7D7E7F" +
			"808182838485868788898A8B8C8D8E8F" +
			"909192939495969798999A9B9C9D9E9F" +
			"A0A1A2A3A4A5A6A7A8A9AAABACADAEAF" +
			"B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" +
			"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF" +
			"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF" +
			"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF" +
			"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";

		const string HexStringLower =
			"000102030405060708090a0b0c0d0e0f" +
			"101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f" +
			"303132333435363738393a3b3c3d3e3f" +
			"404142434445464748494a4b4c4d4e4f" +
			"505152535455565758595a5b5c5d5e5f" +
			"606162636465666768696a6b6c6d6e6f" +
			"707172737475767778797a7b7c7d7e7f" +
			"808182838485868788898a8b8c8d8e8f" +
			"909192939495969798999a9b9c9d9e9f" +
			"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
			"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
			"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
			"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
			"e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
			"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

		byte[] bytes;
		string result, expected;
		Base32Config testConfig = Base32Config.Rfc;

		// our implementation accepts only string length multiples of 5
		[TestMethod]
		public void Base32_Tests()
		{
			bytes = Encoding.ASCII.GetBytes("");
			expected = "";
			result = Base32Extensions.ToBase32(bytes, testConfig);
			Assert.AreEqual<string>(result, expected);
			result = Base32Extensions.ToBase32(new ArraySegment<byte>(bytes), testConfig);
			Assert.AreEqual<string>(result, expected);
			Assert.IsTrue(Enumerable.SequenceEqual(bytes, Base32Extensions.FromBase32(expected, testConfig)));

			bytes = Encoding.ASCII.GetBytes("fooba");
			expected = "MZXW6YTB";
			result = Base32Extensions.ToBase32(bytes, testConfig);
			Assert.AreEqual<string>(result, expected);
			result = Base32Extensions.ToBase32(new ArraySegment<byte>(bytes), testConfig);
			Assert.AreEqual<string>(result, expected);
			Assert.IsTrue(Enumerable.SequenceEqual(bytes, Base32Extensions.FromBase32(expected, testConfig)));
		}

		[TestMethod]
		public void Base16_BasicTests()
		{
			bytes = Encoding.ASCII.GetBytes("");
			expected = "";
			result = Base16Extensions.ToBase16(bytes);
			Assert.AreEqual<string>(result, expected);
			result = Base16Extensions.ToBase16(new ArraySegment<byte>(bytes));
			Assert.AreEqual<string>(result, expected);
			Assert.IsTrue(Enumerable.SequenceEqual(bytes, Base16Extensions.FromBase16(expected)));

			bytes = Encoding.ASCII.GetBytes("f");
			expected = "66";
			result = Base16Extensions.ToBase16(bytes);
			Assert.AreEqual<string>(result, expected);
			result = Base16Extensions.ToBase16(new ArraySegment<byte>(bytes));
			Assert.AreEqual<string>(result, expected);
			Assert.IsTrue(Enumerable.SequenceEqual(bytes, Base16Extensions.FromBase16(expected)));

			bytes = Encoding.ASCII.GetBytes("fo");
			expected = "666F";
			result = Base16Extensions.ToBase16(bytes);
			Assert.AreEqual<string>(result, expected);
			result = Base16Extensions.ToBase16(new ArraySegment<byte>(bytes));
			Assert.AreEqual<string>(result, expected);
			Assert.IsTrue(Enumerable.SequenceEqual(bytes, Base16Extensions.FromBase16(expected)));

			bytes = Encoding.ASCII.GetBytes("foo");
			expected = "666F6F";
			result = Base16Extensions.ToBase16(bytes);
			Assert.AreEqual<string>(result, expected);
			result = Base16Extensions.ToBase16(new ArraySegment<byte>(bytes));
			Assert.AreEqual<string>(result, expected);
			Assert.IsTrue(Enumerable.SequenceEqual(bytes, Base16Extensions.FromBase16(expected)));

			bytes = Encoding.ASCII.GetBytes("fooba");
			expected = "666F6F6261";
			result = Base16Extensions.ToBase16(bytes);
			Assert.AreEqual<string>(result, expected);
			result = Base16Extensions.ToBase16(new ArraySegment<byte>(bytes));
			Assert.AreEqual<string>(result, expected);
			Assert.IsTrue(Enumerable.SequenceEqual(bytes, Base16Extensions.FromBase16(expected)));

			bytes = Encoding.ASCII.GetBytes("foobar");
			expected = "666F6F626172";
			result = Base16Extensions.ToBase16(bytes);
			Assert.AreEqual<string>(result, expected);
			result = Base16Extensions.ToBase16(new ArraySegment<byte>(bytes));
			Assert.AreEqual<string>(result, expected);
			Assert.IsTrue(Enumerable.SequenceEqual(bytes, Base16Extensions.FromBase16(expected)));
		}//Base16_BasicTests()

		[TestMethod]
		public void Base16_ToHexStringUpper()
		{
			Assert.AreEqual(HexStringUpper, test_bytes.ToBase16());
		}


		[TestMethod]
		[ExpectedException(typeof(NullReferenceException))]
		public void Base16_ToHexStringUpperNull()
		{
			Extensions.Base16Extensions.ToBase16(null);
		}

		[TestMethod]
		public void Base16_FromHexStringUpperCase()
		{
			Assert.IsTrue(test_bytes.SequenceEqual(HexStringUpper.FromBase16()));
		}

		[TestMethod]
		public void Base16_FromHexStringLowerCase()
		{
			Assert.IsTrue(test_bytes.SequenceEqual(HexStringLower.FromBase16()));
		}

		[TestMethod]
		[ExpectedException(typeof(NullReferenceException))]
		public void Base16_FromHexStringNull()
		{
			Extensions.Base16Extensions.FromBase16(null);
		}
	}//class

	[TestClass]
	public class Base16_Modhex_Tests
	{
		Func<byte[], string> toModhex = binary => Base16Extensions.ToBase16(binary, Base16Config.HexYubiModhex);
		Func<string, byte[]> fromModhex = str16 => Base16Extensions.FromBase16(str16, Base16Config.HexYubiModhex);

		void TestRun(string modhex, string hex)
		{
			byte[] modhexBytes = fromModhex(modhex);
			byte[] hexBytes = hex.FromBase16();
			string msg = $"modhex:\"{modhex}\", hex:\"{hex}\"";

			Assert.IsTrue(Enumerable.SequenceEqual(modhexBytes, hexBytes), msg);
			Assert.IsTrue(toModhex(modhexBytes) == modhex, msg);
		}

		// test cases from YubiKey Manual v3.4 and Yubico forums
		Dictionary<string, string> testcases = new Dictionary<string, string>
		{
			["fi"] = "47",
			["nlltvcct"] = "baadf00d",
			["hknhfjbrjnlnldnhcujvddbikngjrtgh"] = "69b6481c8baba2b60e8f22179b58cd56",
			["chjdkgdteehevddghgfngjlienbebdgk"] = "0682952d3363f225654b58a73b131259",
			["dteffuje"] = "2d344e83",
			["ekhgjhbctrgn"] = "39658610dc5b",
		};

		[TestMethod]
		public void Base16_Modhex_Test()
		{
			foreach (var test in testcases) TestRun(modhex: test.Key, hex: test.Value);
		}// Base16_Modhex_Test()
	}//class Base16_Modhex_Tests

	[TestClass]
	public class Base64_ToB64Url_Tests
	{
		[TestMethod]
		public void Base64_ToB64Url_Test()
		{
			var rnd = new CryptoRandom();
			Parallel.For(1, 5000, i =>
			{
				var byteArray = rnd.NextBytes(i);
				var offset = 0;
				var count = Math.Max(i, i - rnd.Next(10));
				var byteSegment = new ArraySegment<byte>(byteArray, offset, count);

				var b64url = byteSegment.ToB64Url();
				var b64 = byteSegment.ToB64();

				Assert.IsTrue(b64url + b64[b64.Length - 1] == b64);
				Assert.IsTrue(Enumerable.SequenceEqual(byteSegment, b64url.FromB64Url()));
			});

			{
				string result = null;

				result = new byte[0].ToB64();
				Assert.IsTrue(result == string.Empty);
				result = new byte[0].ToB64Url();
				Assert.IsTrue(result == string.Empty);

				result = new ArraySegment<byte>(new byte[0]).ToB64();
				Assert.IsTrue(result == string.Empty);
				result = new ArraySegment<byte>(new byte[0]).ToB64Url();
				Assert.IsTrue(result == string.Empty);
			}
		}// Base64_ToB64Url_Test()
	}// class Base64_ToB64Url_Tests()

	//http://tools.ietf.org/html/rfc5869 (Appendix A test vectors)
	[TestClass]
	public class HKDF_Test
	{
		[TestMethod]
		public void HDKF_Testcase1()
		{
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA256(), HMACFactories.HMACSHA256 };
			foreach (var hmacFactory in hmacFactories)
			{
				using (var hkdf = new HKDF(hmacFactory,
					ikm: Enumerable.Repeat<byte>(0x0b, 22).ToArray(),
					salt: Enumerable.Range(0, 13).Select(i => (byte)i).ToArray(),
					context: Enumerable.Range(0xf0, 10).Select(i => (byte)i).ToArray()))
				{
					var result = hkdf.GetBytes(countBytes: 42);
					var expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865".FromBase16();
					Assert.IsTrue(Enumerable.SequenceEqual(result, expected)); // "expected" is OKM in the document
				}
			}
		}//1

		[TestMethod]
		public void HDKF_Testcase2()
		{
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA256(), HMACFactories.HMACSHA256 };
			foreach (var hmacFactory in hmacFactories)
			{
				using (var hkdf = new HKDF(hmacFactory,
					ikm: Enumerable.Range(0x00, 80).Select(i => (byte)i).ToArray(),
					salt: Enumerable.Range(0x60, 80).Select(i => (byte)i).ToArray(),
					context: Enumerable.Range(0xb0, 80).Select(i => (byte)i).ToArray()))
				{
					var result = hkdf.GetBytes(countBytes: 82);
					var expected = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87".FromBase16();
					Assert.IsTrue(Enumerable.SequenceEqual(result, expected)); // "expected" is OKM in the document
				}
			}
		}//2

		[TestMethod]
		public void HDKF_Testcase3()
		{
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA256(), HMACFactories.HMACSHA256 };
			foreach (var hmacFactory in hmacFactories)
			{
				using (var hkdf = new HKDF(hmacFactory,
					ikm: Enumerable.Repeat<byte>(0x0b, 22).ToArray(),
					salt: new byte[] { },
					context: new byte[] { }))
				{
					var result = hkdf.GetBytes(countBytes: 42);
					var expected = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8".FromBase16();
					Assert.IsTrue(Enumerable.SequenceEqual(result, expected)); // "expected" is OKM in the document
				}
			}
		}//3

		[TestMethod]
		public void HDKF_Testcase4()
		{
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA1(), HMACFactories.HMACSHA1 };
			foreach (var hmacFactory in hmacFactories)
			{
				using (var hkdf = new HKDF(hmacFactory,
					ikm: Enumerable.Repeat<byte>(0x0b, 11).ToArray(),
					salt: Enumerable.Range(0x00, 13).Select(i => (byte)i).ToArray(),
					context: Enumerable.Range(0xf0, 10).Select(i => (byte)i).ToArray()))
				{
					var result = hkdf.GetBytes(countBytes: 42);
					var expected = "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896".FromBase16();
					Assert.IsTrue(Enumerable.SequenceEqual(result, expected)); // "expected" is OKM in the document
				}
			}
		}//4

		[TestMethod]
		public void HDKF_Testcase5()
		{
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA1(), HMACFactories.HMACSHA1 };
			foreach (var hmacFactory in hmacFactories)
			{
				using (var hkdf = new HKDF(hmacFactory,
					ikm: Enumerable.Range(0x00, 80).Select(i => (byte)i).ToArray(),
					salt: Enumerable.Range(0x60, 80).Select(i => (byte)i).ToArray(),
					context: Enumerable.Range(0xb0, 80).Select(i => (byte)i).ToArray()))
				{
					var result = hkdf.GetBytes(countBytes: 82);
					var expected = "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4".FromBase16();
					Assert.IsTrue(Enumerable.SequenceEqual(result, expected)); // "expected" is OKM in the document
				}
			}
		}//5

		[TestMethod]
		public void HDKF_Testcase6()
		{
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA1(), HMACFactories.HMACSHA1 };
			foreach (var hmacFactory in hmacFactories)
			{
				using (var hkdf = new HKDF(hmacFactory,
					ikm: Enumerable.Repeat<byte>(0x0b, 22).ToArray(),
					salt: new byte[] { },
					context: new byte[] { }))
				{
					var result = hkdf.GetBytes(countBytes: 42);
					var expected = "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918".FromBase16();
					Assert.IsTrue(Enumerable.SequenceEqual(result, expected)); // "expected" is OKM in the document
				}
			}
		}//6

		[TestMethod]
		public void HDKF_Testcase7()
		{
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA1(), HMACFactories.HMACSHA1 };
			foreach (var hmacFactory in hmacFactories)
			{
				using (var hkdf = new HKDF(hmacFactory,
					ikm: Enumerable.Repeat<byte>(0x0c, 22).ToArray(),
					salt: null,
					context: new byte[] { }))
				{
					var result = hkdf.GetBytes(countBytes: 42);
					var expected = "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48".FromBase16();
					Assert.IsTrue(Enumerable.SequenceEqual(result, expected)); // "expected" is OKM in the document
				}
			}
		}//7

	}//HKDF_Tests

	[TestClass]
	public class EtM_CBC_TestClass
	{
		[TestMethod]
		public void EtM_CBC_Sanity()
		{
			var rnd = new CryptoRandom();
			const int plaintextOffset = 16;

			for (int i = 0; i < 2000; ++i)
			{
				var plaintext = new byte[rnd.Next(plaintextOffset + plaintextOffset, 50 * 1024)];
				var plaintextSegment = new ArraySegment<byte>(array: plaintext, offset: plaintextOffset /* some non-zero offset */, count: plaintext.Length - plaintextOffset - plaintextOffset);
				rnd.NextBytes(plaintext);
				var masterkey = new byte[rnd.Next(0, 64)];
				rnd.NextBytes(masterkey);

				var salt = new byte[rnd.Next(0, 64)];
				rnd.NextBytes(salt);
				var saltSegment = new ArraySegment<byte>(salt);

				var ciphertext = EtM_CBC.Encrypt(masterkey, plaintextSegment, saltSegment);
				var ciphertext_with_padding = new byte[ciphertext.Length + plaintextOffset + plaintextOffset];
				Utils.BlockCopy(ciphertext, 0, ciphertext_with_padding, plaintextOffset, ciphertext.Length);

				var ciphertextSegment = new ArraySegment<byte>(array: ciphertext_with_padding, offset: plaintextOffset, count: ciphertext.Length);
				var decryptedtext = EtM_CBC.Decrypt(masterkey, ciphertextSegment, saltSegment);
				Assert.IsTrue(Utils.ConstantTimeEqual(new ArraySegment<byte>(decryptedtext), plaintextSegment));

				Assert.IsTrue(EtM_CBC.Authenticate(masterkey, ciphertextSegment, saltSegment));
			}//for
		}//EtM_CBC_Sanity()
	}//EtM_CBC_TestClass

	[TestClass]
	public class SP800_108_Test
	{
		// http://csrc.nist.gov/groups/STM/cavp/#10

		HMAC hmac;
		byte[] buffer;
		ArraySegment<byte> outBuffer;
		string expected, calculated;

		[TestMethod]
		public void SP800_108_SHA1()
		{
			/*
				[PRF=HMAC_SHA1]
				[CTRLOCATION=BEFORE_FIXED]
				[RLEN=32_BITS]
			*/
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA1(), HMACFactories.HMACSHA1 };
			foreach (var hmacFactory in hmacFactories)
			{
				hmac = hmacFactory();

				for (int i = 0; i < 2; ++i)
				{
					// COUNT=0
					hmac.Key = "f7591733c856593565130975351954d0155abf3c".FromBase16();
					buffer = "000000018e347ef55d5f5e99eab6de706b51de7ce004f3882889e259ff4e5cff102167a5a4bd711578d4ce17dd9abe56e51c1f2df950e2fc812ec1b217ca08d6".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[128 / 8]);
					expected = "34fe44b0d8c41b93f5fa64fb96f00e5b";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=10
					hmac.Key = "c1efb8d25affc61ed060d994fcd5017c2adfc388".FromBase16();
					buffer = "00000001b92fc055057fec71b9c53e7c44872423a57ed186d6ba66d980fecd1253bf71479320b7bf38d505ef79ca4d62d78ca662642cdcedb99503ea04c1dbe8".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[256 / 8]);
					expected = "8db784cf90b573b06f9b7c7dca63a1ea16d93ee7d70ff9d87fa2558e83dc4eaa";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=20
					hmac.Key = "e02ba5d5c410e855bbd13f840124273e6b864237".FromBase16();
					buffer = "00000001b14e227b4438f973d671141c6246acdc794eee91bc7efd1d5ff02a7b8fb044009fb6f1f0f64f35365fb1098e1995a34f8b70a71ed0265ed17ae7ae40".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[160 / 8]);
					expected = "f077c2d5d36a658031c74ef5a66aa48b4456530a";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=30
					hmac.Key = "693adb9037184627ad300f176985bd379f388a95".FromBase16();
					buffer = "000000017f09570c2d9304ec743ab845a8761c126c18f5cf72358eada2b5d1deb43dc6a0f4ff8f933bef7af0bcfacb33fa07f8ca04a06afe231835d5075996be".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[320 / 8]);
					expected = "52f55f51010e9bd78e4f58cab274ecafa561bd4e0f20da84f0303a1e5ff9bebc514361ec6df5c77e";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
			}
		}// SP800_108_SHA1

		[TestMethod]
		public void SP800_108_SHA256()
		{
			/*
				[PRF=HMAC_SHA256]
				[CTRLOCATION=BEFORE_FIXED]
				[RLEN=32_BITS]
			*/
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA256(), HMACFactories.HMACSHA256 };
			foreach (var hmacFactory in hmacFactories)
			{
				hmac = hmacFactory();

				for (int i = 0; i < 2; ++i)
				{
					// COUNT=0
					hmac.Key = "dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0".FromBase16();
					buffer = "0000000101322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[128 / 8]);
					expected = "10621342bfb0fd40046c0e29f2cfdbf0";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=10
					hmac.Key = "e204d6d466aad507ffaf6d6dab0a5b26152c9e21e764370464e360c8fbc765c6".FromBase16();
					buffer = "000000017b03b98d9f94b899e591f3ef264b71b193fba7043c7e953cde23bc5384bc1a6293580115fae3495fd845dadbd02bd6455cf48d0f62b33e62364a3a80".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[256 / 8]);
					expected = "770dfab6a6a4a4bee0257ff335213f78d8287b4fd537d5c1fffa956910e7c779";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=20
					hmac.Key = "dc60338d884eecb72975c603c27b360605011756c697c4fc388f5176ef81efb1".FromBase16();
					buffer = "0000000144d7aa08feba26093c14979c122c2437c3117b63b78841cd10a4bc5ed55c56586ad8986d55307dca1d198edcffbc516a8fbe6152aa428cdd800c062d".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[160 / 8]);
					expected = "29ac07dccf1f28d506cd623e6e3fc2fa255bd60b";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=30
					hmac.Key = "c4bedbddb66493e7c7259a3bbbc25f8c7e0ca7fe284d92d431d9cd99a0d214ac".FromBase16();
					buffer = "000000011c69c54766791e315c2cc5c47ecd3ffab87d0d273dd920e70955814c220eacace6a5946542da3dfe24ff626b4897898cafb7db83bdff3c14fa46fd4b".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[320 / 8]);
					expected = "1da47638d6c9c4d04d74d4640bbd42ab814d9e8cc22f4326695239f96b0693f12d0dd1152cf44430";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
			}
		}// SP800_108_SHA256

		[TestMethod]
		public void SP800_108_SHA384()
		{
			/*
				[PRF=HMAC_SHA384]
				[CTRLOCATION=BEFORE_FIXED]
				[RLEN=32_BITS]
			*/
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA384(), HMACFactories.HMACSHA384 };
			foreach (var hmacFactory in hmacFactories)
			{
				hmac = hmacFactory();

				for (int i = 0; i < 2; ++i)
				{
					// COUNT=0
					hmac.Key = "216ed044769c4c3908188ece61601af8819c30f501d12995df608e06f5e0e607ab54f542ee2da41906dfdb4971f20f9d".FromBase16();
					buffer = "00000001638e9506a2c7be69ea346b84629a010c0e225b7548f508162c89f29c1ddbfd70472c2b58e7dc8aa6a5b06602f1c8ed4948cda79c62708218e26ac0e2".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[128 / 8]);
					expected = "d4b144bb40c7cabed13963d7d4318e72";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=10
					hmac.Key = "8fca201473433f2dc8f6ae51e48de1a5654ce687e711d2d65f0dc5da6fee9a6a3db9d8535d3e4455ab53d35850c88272".FromBase16();
					buffer = "00000001195bd88aa2d4211912334fe2fd9bd24522f7d9fb08e04747609bc34f2538089a9d28bbc70b2e1336c3643753cec6e5cd3f246caa915e3c3a6b94d3b6".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[256 / 8]);
					expected = "f51ac86b0f462388d189ed0197ef99c2ff3a65816d8442e5ea304397b98dd11f";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=20
					hmac.Key = "bc3157b8932e88d1b1cf8e4622137010a242d3527b1d23d6d9c0db9cc9edfc20e5135de823977bf4defafae44d6cdab6".FromBase16();
					buffer = "00000001b42a8e43cc2d4e5c69ee5e4f6b19ff6b8071d26bab4dfe45650b92b1f47652d25162d4b61441d8448c54918ae568ae2fb53091c624dbfffacee51d88".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[160 / 8]);
					expected = "91314bdf542162031643247d6507838eaba50f1a";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=30
					hmac.Key = "582f968a54b8797b9ea8c655b42e397adb73d773b1984b1e1c429cd597b8015d2f91d59e4136a9d523bf6491a4733c7a".FromBase16();
					buffer = "00000001e6d3c193eff34e34f8b7b00e66565aeb01f63206bb27e27aa281592afc06ae1ec5b7eb97a39684ce773d7c3528f2667c1f5d428406e78ce4cf39f652".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[320 / 8]);
					expected = "691726c111e5030b5f9657069107861ecc18bc5835a814c3d2e5092c901cb1fb6c1a7cd3eb0be2a7";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
			}
		}// SP800_108_SHA384

		[TestMethod]
		public void SP800_108_SHA512()
		{
			/*
				[PRF=HMAC_SHA512]
				[CTRLOCATION=BEFORE_FIXED]
				[RLEN=32_BITS]
			*/
			var hmacFactories = new Func<HMAC>[] { () => new HMACSHA512(), HMACFactories.HMACSHA512 };
			foreach (var hmacFactory in hmacFactories)
			{
				hmac = hmacFactory();

				for (int i = 0; i < 2; ++i)
				{
					// COUNT=0
					hmac.Key = "dd5dbd45593ee2ac139748e7645b450f223d2ff297b73fd71cbcebe71d41653c950b88500de5322d99ef18dfdd30428294c4b3094f4c954334e593bd982ec614".FromBase16();
					buffer = "00000001b50b0c963c6b3034b8cf19cd3f5c4ebe4f4985af0c03e575db62e6fdf1ecfe4f28b95d7ce16df85843246e1557ce95bb26cc9a21974bbd2eb69e8355".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[128 / 8]);
					expected = "e5993bf9bd2aa1c45746042e12598155";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=10
					hmac.Key = "5be2bf7f5e2527e15fe65cde4507d98ba55457006867de9e4f36645bcff4ca38754f92898b1c5544718102593b8c26d45d1fceaea27d97ede9de8b9ebfe88093".FromBase16();
					buffer = "00000001004b13c1f628cb7a00d9498937bf437b71fe196cc916c47d298fa296c6b86188073543bbc66b7535eb17b5cf43c37944b6ca1225298a9e563413e5bb".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[256 / 8]);
					expected = "cee0c11be2d8110b808f738523e718447d785878bbb783fb081a055160590072";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=20
					hmac.Key = "9dd03864a31aa4156ca7a12000f541680ce0a5f4775eef1088ac13368200b447a78d0bf14416a1d583c54b0f11200ff4a8983dd775ce9c0302d262483e300ae6".FromBase16();
					buffer = "00000001037369f142d669fca9e87e9f37ae8f2c8d506b753fdfe8a3b72f75cac1c50fa1f8620883b8dcb8dcc67adcc95e70aa624adb9fe1b2cb396692b0d2e8".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[160 / 8]);
					expected = "96e8d1bc01dc95c0bf42c3c38fc54c090373ced4";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
				for (int i = 0; i < 2; ++i)
				{
					// COUNT=30
					hmac.Key = "a9f4a2c5af839867f5db5a1e520ab3cca72a166ca60de512fd7fe7e64cf94f92cf1d8b636175f293e003275e021018c3f0ede495997a505ec9a2afeb0495be57".FromBase16();
					buffer = "000000018e9db3335779db688bcfe096668d9c3bc64e193e3529c430e68d09d56c837dd6c0f94678f121a68ee1feea4735da85a49d34a5290aa39f7b40de435f".FromBase16();
					outBuffer = new ArraySegment<byte>(new byte[320 / 8]);
					expected = "6db880daac98b078ee389a2164252ded61322d661e2b49247ea921e544675d8f17af2bf66dd40d81";
					SP800_108_Ctr.DeriveKey(hmac, buffer, ref outBuffer);
					calculated = outBuffer.ToBase16(Base16Config.HexLowercase);
					Assert.IsTrue(calculated == expected);
				}
			}
		}// SP800_108_SHA512

		[TestMethod]
		public void SP800_108_Extra1()
		{
			// SP800_108 expected values from
			// https://github.com/aspnet/DataProtection/blob/cd33cbfc8fc3945b531bc3cd1e25f53a0dc89baf/test/Microsoft.AspNet.Security.DataProtection.Test/SP800_108/SP800_108Tests.cs

			// Arrange
			byte[] kdk = Encoding.UTF8.GetBytes("kdk");
			byte[] label = Encoding.UTF8.GetBytes("label");
			byte[] contextHeader = Encoding.UTF8.GetBytes("contextHeader");
			byte[] context = Encoding.UTF8.GetBytes("context");

			var labelSegment = new ArraySegment<byte>(label);
			var contextSegment = new ArraySegment<byte>(contextHeader.Concat(context).ToArray());

			byte[] derivedOutput;

			// Act & assert
			derivedOutput = new byte[64 - 1];
			SP800_108_Ctr.DeriveKey(HMACFactories.HMACSHA512, kdk, labelSegment, contextSegment, new ArraySegment<byte>(derivedOutput));
			Assert.IsTrue(Enumerable.SequenceEqual(derivedOutput, Convert.FromBase64String("V47WmHzPSkdC2vkLAomIjCzZlDOAetll3yJLcSvon7LJFjJpEN+KnSNp+gIpeydKMsENkflbrIZ/3s6GkEaH")));

			derivedOutput = new byte[64];
			SP800_108_Ctr.DeriveKey(HMACFactories.HMACSHA512, kdk, labelSegment, contextSegment, new ArraySegment<byte>(derivedOutput));
			Assert.IsTrue(Enumerable.SequenceEqual(derivedOutput, Convert.FromBase64String("mVaFM4deXLl610CmnCteNzxgbM/VkmKznAlPauHcDBn0le06uOjAKLHx0LfoU2/Ttq9nd78Y6Nk6wArmdwJgJg==")));

			derivedOutput = new byte[64 + 1];
			SP800_108_Ctr.DeriveKey(HMACFactories.HMACSHA512, kdk, labelSegment, contextSegment, new ArraySegment<byte>(derivedOutput));
			Assert.IsTrue(Enumerable.SequenceEqual(derivedOutput, Convert.FromBase64String("GaHPeqdUxriFpjRtkYQYWr5/iqneD/+hPhVJQt4rXblxSpB1UUqGqL00DMU/FJkX0iMCfqUjQXtXyfks+p++Ev4=")));
		}

		[TestMethod]
		public void SP800_108_Extra2()
		{
			// SP800_108 expected values from
			// https://github.com/aspnet/DataProtection/blob/cd33cbfc8fc3945b531bc3cd1e25f53a0dc89baf/test/Microsoft.AspNet.Security.DataProtection.Test/SP800_108/SP800_108Tests.cs

			// Arrange
			byte[] kdk = Enumerable.Range(0, 50000).Select(i => (byte)i).ToArray();
			byte[] label = Encoding.UTF8.GetBytes("label");
			byte[] contextHeader = Encoding.UTF8.GetBytes("contextHeader");
			byte[] context = Encoding.UTF8.GetBytes("context");

			var labelSegment = new ArraySegment<byte>(label);
			var contextSegment = new ArraySegment<byte>(contextHeader.Concat(context).ToArray());

			byte[] derivedOutput;

			// Act & assert
			derivedOutput = new byte[64 - 1];
			SP800_108_Ctr.DeriveKey(HMACFactories.HMACSHA512, kdk, labelSegment, contextSegment, new ArraySegment<byte>(derivedOutput));
			Assert.IsTrue(Enumerable.SequenceEqual(derivedOutput, Convert.FromBase64String("rt2hM6kkQ8hAXmkHx0TU4o3Q+S7fie6b3S1LAq107k++P9v8uSYA2G+WX3pJf9ZkpYrTKD7WUIoLkgA1R9lk")));

			derivedOutput = new byte[64];
			SP800_108_Ctr.DeriveKey(HMACFactories.HMACSHA512, kdk, labelSegment, contextSegment, new ArraySegment<byte>(derivedOutput));
			Assert.IsTrue(Enumerable.SequenceEqual(derivedOutput, Convert.FromBase64String("RKiXmHSrWq5gkiRSyNZWNJrMR0jDyYHJMt9odOayRAE5wLSX2caINpQmfzTH7voJQi3tbn5MmD//dcspghfBiw==")));

			derivedOutput = new byte[64 + 1];
			SP800_108_Ctr.DeriveKey(HMACFactories.HMACSHA512, kdk, labelSegment, contextSegment, new ArraySegment<byte>(derivedOutput));
			Assert.IsTrue(Enumerable.SequenceEqual(derivedOutput, Convert.FromBase64String("KedXO0zAIZ3AfnPqY1NnXxpC3HDHIxefG4bwD3g6nWYEc5+q7pjbam71Yqj0zgHMNC9Z7BX3wS1/tajFocRWZUk=")));
		}
	}//class SP800_108_Test

	[TestClass]
	public class AesCtrCryptoTransform_TestClass // RFC_3686 & NIST_SP800_38a AES CTR test vectors
	{
		byte[] key;
		ArraySegment<byte> counterBlockSegment;
		ArraySegment<byte> plaintext;
		string expectedHex;
		Func<Aes> aesFactory = Cipher.AesFactories.Aes;

		void RunTest()
		{
			using (var ctrTransform = new Cipher.AesCtrCryptoTransform(key, counterBlockSegment, aesFactory))
			{
				var computedHex = ctrTransform.TransformFinalBlock(plaintext.Array, plaintext.Offset, plaintext.Count).ToBase16();
				Assert.IsTrue(computedHex == expectedHex);
			}

			var computedHex2 = "";
			using (var ctrTransform = new Cipher.AesCtrCryptoTransform(key, counterBlockSegment, aesFactory))
			{
				var outputBuffer = new byte[1];
				var sb = new StringBuilder(expectedHex.Length);

				for (int i = 0; i < plaintext.Count; ++i)
				{
					ctrTransform.TransformBlock(plaintext.Array, plaintext.Offset + i, 1, outputBuffer, 0);
					sb.Append(outputBuffer.ToBase16());
				}
				computedHex2 = sb.ToString();
			}

			Assert.IsTrue(computedHex2 == expectedHex);
		}// RunTest()

		[TestMethod]
		public void AesCtrCryptoTransform_Tests()
		{
			//AES 128 CTR tests
			{
				key = "AE6852F8121067CC4BF7A5765577F39E".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("00000030000000000000000000000001".FromBase16());
				plaintext = new ArraySegment<byte>("53696E676C6520626C6F636B206D7367".FromBase16());
				expectedHex = "E4095D4FB7A7B3792D6175A3261311B8";
				RunTest();

				key = "7E24067817FAE0D743D6CE1F32539163".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("006CB6DBC0543B59DA48D90B00000001".FromBase16());
				plaintext = new ArraySegment<byte>("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F".FromBase16());
				expectedHex = "5104A106168A72D9790D41EE8EDAD388EB2E1EFC46DA57C8FCE630DF9141BE28";
				RunTest();

				key = "7691BE035E5020A8AC6E618529F9A0DC".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("00E0017B27777F3F4A1786F000000001".FromBase16());
				plaintext = new ArraySegment<byte>("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223".FromBase16());
				expectedHex = "C1CF48A89F2FFDD9CF4652E9EFDB72D74540A42BDE6D7836D59A5CEAAEF3105325B2072F";
				RunTest();

				// NIST test
				key = "2b7e151628aed2a6abf7158809cf4f3c".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".FromBase16());
				plaintext = new ArraySegment<byte>("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710".FromBase16());
				expectedHex = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee".ToUpperInvariant();
				RunTest();
			}

			//AES 192 CTR tests
			{
				key = "16AF5B145FC9F579C175F93E3BFB0EED863D06CCFDB78515".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("0000004836733C147D6D93CB00000001".FromBase16());
				plaintext = new ArraySegment<byte>("53696E676C6520626C6F636B206D7367".FromBase16());
				expectedHex = "4B55384FE259C9C84E7935A003CBE928";
				RunTest();

				key = "7C5CB2401B3DC33C19E7340819E0F69C678C3DB8E6F6A91A".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("0096B03B020C6EADC2CB500D00000001".FromBase16());
				plaintext = new ArraySegment<byte>("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F".FromBase16());
				expectedHex = "453243FC609B23327EDFAAFA7131CD9F8490701C5AD4A79CFC1FE0FF42F4FB00";
				RunTest();

				key = "02BF391EE8ECB159B959617B0965279BF59B60A786D3E0FE".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("0007BDFD5CBD60278DCC091200000001".FromBase16());
				plaintext = new ArraySegment<byte>("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223".FromBase16());
				expectedHex = "96893FC55E5C722F540B7DD1DDF7E758D288BC95C69165884536C811662F2188ABEE0935";
				RunTest();

				// NIST test
				key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".FromBase16());
				plaintext = new ArraySegment<byte>("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710".FromBase16());
				expectedHex = "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050".ToUpperInvariant();
				RunTest();
			}

			//AES 256 CTR tests
			{
				key = "776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("00000060DB5672C97AA8F0B200000001".FromBase16());
				plaintext = new ArraySegment<byte>("53696E676C6520626C6F636B206D7367".FromBase16());
				expectedHex = "145AD01DBF824EC7560863DC71E3E0C0";
				RunTest();

				key = "F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("00FAAC24C1585EF15A43D87500000001".FromBase16());
				plaintext = new ArraySegment<byte>("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F".FromBase16());
				expectedHex = "F05E231B3894612C49EE000B804EB2A9B8306B508F839D6A5530831D9344AF1C";
				RunTest();

				key = "FF7A617CE69148E4F1726E2F43581DE2AA62D9F805532EDFF1EED687FB54153D".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("001CC5B751A51D70A1C1114800000001".FromBase16());
				plaintext = new ArraySegment<byte>("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223".FromBase16());
				expectedHex = "EB6C52821D0BBBF7CE7594462ACA4FAAB407DF866569FD07F48CC0B583D6071F1EC0E6B8";
				RunTest();

				// NIST test
				key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".FromBase16();
				counterBlockSegment = new ArraySegment<byte>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".FromBase16());
				plaintext = new ArraySegment<byte>("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710".FromBase16());
				expectedHex = "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6".ToUpperInvariant();
				RunTest();
			}
		}//AesCtrCryptoTransform_Tests()
	}//AesCtrCryptoTransform_TestClass

	[TestClass]
	public class EtM_CTR_TestClass
	{

		[TestMethod]
		public void EtM_CTR_Sanity()
		{
			var rnd = new CryptoRandom();
			const int plaintextOffset = 16;

			for (int i = 0; i < 2000; ++i)
			{
				var plaintext = new byte[rnd.Next(plaintextOffset + plaintextOffset, 50 * 1024)];
				var plaintextSegment = new ArraySegment<byte>(array: plaintext, offset: plaintextOffset /* some non-zero offset */, count: plaintext.Length - plaintextOffset - plaintextOffset);
				rnd.NextBytes(plaintext);
				var masterkey = new byte[rnd.Next(0, 64)];
				rnd.NextBytes(masterkey);

				var salt = new byte[rnd.Next(0, 64)];
				rnd.NextBytes(salt);
				var saltSegment = new ArraySegment<byte>(salt);

				var ciphertext = EtM_CTR.Encrypt(masterkey, plaintextSegment, saltSegment);
				var ciphertext_with_padding = new byte[ciphertext.Length + plaintextOffset + plaintextOffset];
				Utils.BlockCopy(ciphertext, 0, ciphertext_with_padding, plaintextOffset, ciphertext.Length);

				var ciphertextSegment = new ArraySegment<byte>(array: ciphertext_with_padding, offset: plaintextOffset, count: ciphertext.Length);

				var decryptedtext = EtM_CTR.Decrypt(masterkey, ciphertextSegment, saltSegment);
				Assert.IsTrue(Utils.ConstantTimeEqual(new ArraySegment<byte>(decryptedtext), plaintextSegment));

				Assert.IsTrue(EtM_CTR.Authenticate(masterkey, ciphertextSegment, saltSegment));
			}//for
		}//EtM_CTR_Sanity()
	}//EtM_CTR_TestClass

	[TestClass]
	public class TOTP_TestClass
	{
		//https://tools.ietf.org/html/rfc6238#appendix-B
		[TestMethod]
		public void TOTP_Sanity()
		{
			//secret
			byte[] secret = Encoding.ASCII.GetBytes("12345678901234567890");

			//SHA1 test vectors
			var correct_sha1_results = new Tuple<string, int>[]
			{
				Tuple.Create("1970-01-01 00:00:59", 94287082),
				Tuple.Create("2005-03-18 01:58:29", 07081804),
				Tuple.Create("2005-03-18 01:58:31", 14050471),
				Tuple.Create("2009-02-13 23:31:30", 89005924),
				Tuple.Create("2033-05-18 03:33:20", 69279037),
				Tuple.Create("2603-10-11 11:33:20", 65353130),
			};
			const int TOTP_LENGTH = 8;

			for (int i = 0; i < correct_sha1_results.Length; ++i)
			{
				var time = DateTime.ParseExact(correct_sha1_results[i].Item1, "yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
				var totp = Otp.TOTP.GenerateTOTP(secret, () => time, TOTP_LENGTH);
				Assert.IsTrue(totp == correct_sha1_results[i].Item2);

				bool valid = Otp.TOTP.ValidateTOTP(secret, correct_sha1_results[i].Item2, () => time, TOTP_LENGTH);
				Assert.IsTrue(valid);
			}

			Exception exception = null;
			try
			{
				Otp.TOTP.GenerateTOTP(secret, () => Otp.TOTP._unixEpoch.AddDays(-1));
			}
			catch (ArgumentOutOfRangeException ex)
			{
				exception = ex;
			}
			Assert.IsNotNull(exception, "Exception is not thrown when DateTime is less than Unix epoch.");
		}//TOTP_Sanity()

		[TestMethod]
		public void TOTP_GetExpiryTime()
		{
			{
				Func<DateTime> utcFactory = () => DateTime.UtcNow;
				DateTime utc = utcFactory();

				DateTime expiryTime = Otp.TOTP.GetExpiryTime();
				int deltaSeconds = (int)expiryTime.Subtract(utc).TotalSeconds;
				Assert.IsTrue(deltaSeconds >= 0 && deltaSeconds <= 30, $"deltaSeconds outside expected range [{deltaSeconds.ToString()}]");
			}

			{
				CryptoRandom rng = new CryptoRandom();
				Func<DateTime> utcFactory = () => Otp.TOTP._unixEpoch.AddTicks(rng.NextLong(TimeSpan.FromDays(365.25 * 300).Ticks));

				Parallel.For(0, 100000, i =>
				{
					var utc2 = utcFactory();
					DateTime expiryTime = Otp.TOTP.GetExpiryTime(() => utc2);
					int deltaSeconds = (int)expiryTime.Subtract(utc2).TotalSeconds;

					Assert.IsTrue(deltaSeconds >= 0 && deltaSeconds <= 30, $"deltaSeconds outside expected range [{deltaSeconds.ToString()}]");
				});
			}
		}//TOTP_GetExpiryTime()
	}//class TOTP_TestClass

	[TestClass]
	public class ByteArrayExtensions_TestClass
	{
		static readonly CryptoRandom rnd = new CryptoRandom();
		[TestMethod]
		public void CloneBytes()
		{
			for (int i = 0; i < 20; ++i)
			{
				var bytes = rnd.NextBytes(rnd.Next(1, 10000));
				var cloned = ByteArrayExtensions.CloneBytes(bytes);
				var areEqual = Utils.ConstantTimeEqual(bytes, cloned);
				Assert.IsTrue(areEqual);
				Assert.IsTrue(bytes != cloned);
			}
		}//CloneBytes()
	}// class ByteArrayExtensions_TestClass

	[TestClass]
	public class CngKeyExtensions_TestClass
	{
		static readonly CryptoRandom rnd = new CryptoRandom();

		[TestMethod]
		public void CngKey_GetSharedDhmSecret_Sanity()
		{
			var keyA = CngKeyExtensions.CreateNewDhmKey();
			var keyB = CngKeyExtensions.CreateNewDhmKey();

			try
			{
				byte[] staticSharedSecret = CngKeyExtensions.GetSharedDhmSecret(keyA, publicDhmKey: keyB);
				Assert.IsTrue(staticSharedSecret.Length == 48);
			}
			catch (Exception ex)
			{
#if NETSTANDARD
				Assert.IsTrue(ex is PlatformNotSupportedException); // NETSTANDARD 2.0 does not support ECDiffieHellman
#else
				throw;
#endif
			}
		}

		[TestMethod]
		public void CngKey_GetSharedDhmSecret()
		{
			try
			{
				byte[] contextAppend = rnd.NextBytes(rnd.Next(0, 1001));
				byte[] contextPrepend = rnd.NextBytes(rnd.Next(0, 1001));

				byte[] ecdh1_prv_blob, ecdh1_pub_blob;
				byte[] ecdh2_prv_blob, ecdh2_pub_blob;

				{
					var ecdh1 = CngKeyExtensions.CreateNewDhmKey();
					var ecdh2 = CngKeyExtensions.CreateNewDhmKey();

					ecdh1_prv_blob = CngKeyExtensions.GetPrivateBlob(ecdh1);
					ecdh1_pub_blob = CngKeyExtensions.GetPublicBlob(ecdh1);
					ecdh2_prv_blob = CngKeyExtensions.GetPrivateBlob(ecdh2);
					ecdh2_pub_blob = CngKeyExtensions.GetPublicBlob(ecdh2);
				}

				CngKey prv_key1 = ecdh1_prv_blob.ToPrivateKeyFromBlob();
				CngKey pub_key1 = ecdh1_pub_blob.ToPublicKeyFromBlob();
				CngKey prv_key2 = ecdh2_prv_blob.ToPrivateKeyFromBlob();
				CngKey pub_key2 = ecdh2_pub_blob.ToPublicKeyFromBlob();

				byte[] result1 = prv_key1.GetSharedDhmSecret(pub_key2, contextAppend, contextPrepend);
				byte[] result2 = prv_key1.GetSharedDhmSecret(pub_key2, contextAppend, contextPrepend);// same call

				byte[] result3 = Alternative_GetSharedDhmSecret(prv_key1, pub_key2, contextAppend, contextPrepend);
				byte[] result4 = Alternative_GetSharedDhmSecret(prv_key1, pub_key2, contextAppend, contextPrepend);// same call

				byte[] result5 = prv_key2.GetSharedDhmSecret(pub_key1, contextAppend, contextPrepend);
				byte[] result6 = prv_key2.GetSharedDhmSecret(pub_key1, contextAppend, contextPrepend);// same call

				Assert.IsTrue(Enumerable.SequenceEqual(result1, result2));
				Assert.IsTrue(Enumerable.SequenceEqual(result2, result3));
				Assert.IsTrue(Enumerable.SequenceEqual(result3, result4));
				Assert.IsTrue(Enumerable.SequenceEqual(result4, result5));
				Assert.IsTrue(Enumerable.SequenceEqual(result5, result6));
			}
			catch (Exception ex)
			{
#if NETSTANDARD
				Assert.IsTrue(ex is PlatformNotSupportedException); // NETSTANDARD 2.0 does not support ECDiffieHellman
#else
				throw;
#endif
			}
		}//CngKey_GetSharedDhmSecret()

		static byte[] Alternative_GetSharedDhmSecret(CngKey priv_k1, CngKey pub_k2, byte[] contextAppend = null, byte[] contextPrepend = null)
		{
			using (var ecdh = new ECDiffieHellmanCng(priv_k1))
			using (var pub_ecdh = new ECDiffieHellmanCng(pub_k2))
				return ecdh.DeriveKeyFromHash(pub_ecdh.PublicKey, hashAlgorithm: HashAlgorithmName.SHA384, secretAppend: contextAppend, secretPrepend: contextPrepend);
		}//Alternative_GetSharedDhmSecret()
	}// class CngKeyExtensions_TestClass

	[TestClass]
	public class SuiteB_Tests
	{
		static Random _rnd = new Random(Guid.NewGuid().GetHashCode());
		[TestMethod]
		public void SuiteB_Sanity()
		{
			var masterKey = new byte[] { 1, 2, 3 };

			var data = new byte[500];
			for (int i = 0; i < 100; ++i)
			{
				_rnd.NextBytes(data);

				const int pOFFSET = 5;
				const int pCOUNT = 101;

				const int sOFFSET = 67;
				const int sCOUNT = sOFFSET + 17;

				var plaintextSegment = new ArraySegment<byte>(data, pOFFSET, pCOUNT);
				var saltSegment = new ArraySegment<byte>(data, sOFFSET, sCOUNT);

				var ciphertextBytes = SuiteB.Encrypt(masterKey, plaintextSegment, saltSegment);

				var ciphertextBytes_Large = Utils.Combine(new byte[17], ciphertextBytes, new byte[17]);
				var decryptedBytes = SuiteB.Decrypt(masterKey, new ArraySegment<byte>(ciphertextBytes_Large, 17, ciphertextBytes.Length), saltSegment);

				Assert.IsTrue(Enumerable.SequenceEqual(decryptedBytes, plaintextSegment), $"{nameof(i)}={i}");
			}//for
		}// SuiteB_Sanity()
	}// class SuiteB_Tests
}//ns