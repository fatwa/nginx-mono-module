using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Web.Hosting;

namespace Cnaws.Web.Hosting
{
#if(MONO)
    internal class MonoWorkerRequest : SimpleWorkerRequest, IDisposable
    {
        private enum InputDataType
        {
            Unknown,
            Memory,
            File
        }

        private string _root;
        private string _vroot;
        private IntPtr _request;
        private IntPtr _response;

        private string _method;
        private string _rawUrl;
        private string _pathInfo;
        private string _queryString;
        private string _version;
        private string[][] _unknownRequestHeaders;
        private string[] _knownRequestHeaders;

        private EndOfSendNotification _endSend;
        private object _endSendData;
        private string _pathTranslated;

        private byte[] _inputData;
        private InputDataType _inputDataType;
        private int _offset;

        private X509Certificate _clientCert;
        private byte[] _clientRaw;
        private string _certCookie;
        private string _certIssuer;
        private string _certSerial;
        private string _certSubject;

        static MonoWorkerRequest()
        {
            PlatformID pid = Environment.OSVersion.Platform;
            RunningOnWindows = ((int)pid != 128 && pid != PlatformID.Unix && pid != PlatformID.MacOSX);
        }
        public MonoWorkerRequest(string root, string vroot, IntPtr request, IntPtr response)
            : base(string.Empty, string.Empty, null)
        {
            _root = root;
            _vroot = vroot;
            _request = request;
            _response = response;
            _inputDataType = InputDataType.Unknown;
            _offset = 0;

            InitRequestHeader();
        }

        private static bool RunningOnWindows { get; set; }

        private string HostPath => _root;
        private string HostVPath => _vroot;

        protected virtual Encoding Encoding => Encoding.UTF8;

        public X509Certificate ClientCertificate
        {
            get
            {
                if (_clientCert == null && _clientRaw != null)
                    _clientCert = new X509Certificate(_clientRaw);
                return _clientCert;
            }
        }
        public void SetClientCertificate(byte[] rawcert)
        {
            _clientRaw = rawcert;
        }

        public override void CloseConnection()
        {

        }
        public override void EndOfRequest()
        {
            if (_endSend != null)
                _endSend(this, _endSendData);
        }
        public override void FlushResponse(bool finalFlush)
        {

        }
        public override string GetAppPath()
        {
            return HostVPath;
        }
        public override string GetAppPathTranslated()
        {
            return HostPath;
        }
        public override long GetBytesRead()
        {
            throw new NotSupportedException();
        }
        public override byte[] GetClientCertificate()
        {
            return _clientRaw;
        }
        public override byte[] GetClientCertificateBinaryIssuer()
        {
            if (ClientCertificate == null)
                return base.GetClientCertificateBinaryIssuer();
            // TODO: not 100% sure of the content
            return new byte[0];
        }
        public override int GetClientCertificateEncoding()
        {
            if (ClientCertificate == null)
                return base.GetClientCertificateEncoding();
            return 0;
        }
        public override byte[] GetClientCertificatePublicKey()
        {
            if (ClientCertificate == null)
                return base.GetClientCertificatePublicKey();
            return ClientCertificate.GetPublicKey();
        }
        public override DateTime GetClientCertificateValidFrom()
        {
            if (ClientCertificate == null)
                return base.GetClientCertificateValidFrom();
            return DateTime.Parse(ClientCertificate.GetEffectiveDateString());
        }
        public override DateTime GetClientCertificateValidUntil()
        {
            if (ClientCertificate == null)
                return base.GetClientCertificateValidUntil();
            return DateTime.Parse(ClientCertificate.GetExpirationDateString());
        }
        public override string GetFilePath()
        {
            return _pathInfo;
        }
        public override string GetFilePathTranslated()
        {
            if (_pathTranslated == null)
                _pathTranslated = FormatFilePath(string.Concat(HostPath, _pathInfo.TrimStart('/')));
            return _pathTranslated;
        }
        public override string GetHttpVerbName()
        {
            return _method;
        }
        public override string GetHttpVersion()
        {
            return _version;
        }
        public override string GetKnownRequestHeader(int index)
        {
            return _knownRequestHeaders[index];
        }
        public override string GetLocalAddress()
        {
            string address = MonoInternal.GetServerVariable(_request, "SERVER_ADDR");
            if (!string.IsNullOrEmpty(address))
                return address;

            address = AddressFromHostName(MonoInternal.GetServerVariable(_request, "HTTP_HOST"));
            if (!string.IsNullOrEmpty(address))
                return address;

            address = AddressFromHostName(MonoInternal.GetServerVariable(_request, "SERVER_NAME"));
            if (!string.IsNullOrEmpty(address))
                return address;

            return "localhost";
        }
        public override int GetLocalPort()
        {
            string port = MonoInternal.GetServerVariable(_request, "SERVER_PORT");
            if (!string.IsNullOrEmpty(port))
            {
                int ret;
                if (int.TryParse(port, out ret))
                    return ret;
            }
            return 80;
        }
        public override string GetPathInfo()
        {
            return _pathInfo;
        }
        public override byte[] GetPreloadedEntityBody()
        {
            if (IsEntireEntityBodyIsPreloaded())
            {
                if (_inputData == null)
                    _inputData = MonoInternal.GetInputData(_request);
                return _inputData;
            }
            return null;
        }
        public override string GetQueryString()
        {
            return _queryString;
        }
        public override byte[] GetQueryStringRawBytes()
        {
            string queryString = GetQueryString();
            if (queryString == null)
                return null;
            return Encoding.GetBytes(queryString);
        }
        public override string GetRawUrl()
        {
            return _rawUrl;
        }
        public override string GetRemoteAddress()
        {
            string addr = MonoInternal.GetServerVariable(_request, "REMOTE_ADDR");
            if (!string.IsNullOrEmpty(addr))
                return addr;
            return "127.0.0.1";
        }
        public override string GetRemoteName()
        {
            string ip = GetRemoteAddress();
            string name;
            try
            {
                IPHostEntry entry = Dns.GetHostEntry(ip);
                name = entry.HostName;
            }
            catch (Exception)
            {
                name = ip;
            }
            return name;
        }
        public override int GetRemotePort()
        {
            string port = MonoInternal.GetServerVariable(_request, "REMOTE_PORT");
            if (!string.IsNullOrEmpty(port))
            {
                int ret;
                if (int.TryParse(port, out ret))
                    return ret;
            }
            return 80;
        }
        public override string GetServerName()
        {
            return (HostNameFromString(MonoInternal.GetServerVariable(_request, "SERVER_NAME"))
                ?? HostNameFromString(MonoInternal.GetServerVariable(_request, "HTTP_HOST")))
                ?? GetLocalAddress();
        }
        public override string GetServerVariable(string name)
        {
            string value = MonoInternal.GetServerVariable(_request, name);
            if (value != null)
                return value;

            if (IsSecure())
            {
                X509Certificate client = ClientCertificate;
                switch (name)
                {
                    case "CERT_COOKIE":
                        if (_certCookie == null)
                        {
                            if (client == null)
                                _certCookie = string.Empty;
                            else
                                _certCookie = client.GetCertHashString();
                        }
                        return _certCookie;
                    case "CERT_ISSUER":
                        if (_certIssuer == null)
                        {
                            if (client == null)
                                _certIssuer = string.Empty;
                            else
                                _certIssuer = client.Issuer;
                        }
                        return _certIssuer;
                    case "CERT_SERIALNUMBER":
                        if (_certSerial == null)
                        {
                            if (client == null)
                                _certSerial = string.Empty;
                            else
                                _certSerial = client.GetSerialNumberString();
                        }
                        return _certSerial;
                    case "CERT_SUBJECT":
                        if (_certSubject == null)
                        {
                            if (client == null)
                                _certSubject = string.Empty;
                            else
                                _certSubject = client.Subject;
                        }
                        return _certSubject;
                }
            }

            return base.GetServerVariable(name);
        }
        public override string GetUnknownRequestHeader(string name)
        {
            foreach (string[] pair in GetUnknownRequestHeaders())
            {
                if (EqualsIgnoreCase(pair[0], name))
                    return pair[1];
            }

            return base.GetUnknownRequestHeader(name);
        }
        public override string[][] GetUnknownRequestHeaders()
        {
            return _unknownRequestHeaders;
        }
        public override string GetUriPath()
        {
            return _pathInfo; ;
        }
        public override bool HeadersSent()
        {
            return true;
        }
        public override bool IsClientConnected()
        {
            return true;
        }
        public override bool IsEntireEntityBodyIsPreloaded()
        {
            if (_inputDataType == InputDataType.Unknown)
                _inputDataType = (InputDataType)MonoInternal.GetInputDataType(_request);
            return _inputDataType == InputDataType.Memory;
        }
        public override bool IsSecure()
        {
            return MonoInternal.GetServerVariable(_request, "HTTPS") == "on";
        }
        public override string MapPath(string path)
        {
            if (string.IsNullOrEmpty(path))
                return HostPath;

            if (path.StartsWith("~/"))
            {
                if (path.Length > 2)
                    return FormatFilePath(string.Concat(HostPath, path.Substring(2)));
                return HostPath;
            }

            string vpath = HostVPath;
            if (!vpath.EndsWith("/"))
                vpath = string.Concat(vpath, '/');
            if (path.StartsWith(vpath, StringComparison.OrdinalIgnoreCase))
                return FormatFilePath(string.Concat(HostPath, path.Substring(vpath.Length)));

            throw new ArgumentException();
        }
        public override int ReadEntityBody(byte[] buffer, int size)
        {
            int read = MonoInternal.ReadInputData(_request, buffer, size, _offset);
            _offset += read;
            return read;
        }
        public override void SendCalculatedContentLength(int contentLength)
        {

        }
        public override void SendKnownResponseHeader(int index, string value)
        {
            switch (index)
            {
                case HeaderCacheControl:
                case HeaderContentType:
                case HeaderContentRange:
                case HeaderExpires:
                case HeaderLastModified:
                case HeaderAcceptRanges:
                case HeaderEtag:
                case HeaderLocation:
                case HeaderSetCookie:
                case HeaderWwwAuthenticate:
                    MonoInternal.SetHeader(_request, index, value);
                    break;
            }
        }
        public override void SendResponseFromFile(IntPtr handle, long offset, long length)
        {
            using (FileStream stream = new FileStream(new SafeFileHandle(handle, false), FileAccess.Read))
            {
                if (offset < 0 || length <= 0)
                    return;

                long stLength = stream.Length;
                if (offset + length > stLength)
                    length = stLength - offset;

                if (offset > 0)
                    stream.Seek(offset, SeekOrigin.Begin);

                var fileContent = new byte[8192];
                int count = fileContent.Length;
                while (length > 0 && (count = stream.Read(fileContent, 0, count)) != 0)
                {
                    SendResponseFromMemory(fileContent, count);
                    length -= count;
                    // Keep the System. prefix
                    count = (int)Math.Min(length, fileContent.Length);
                }
            }
        }
        public override void SendResponseFromFile(string filename, long offset, long length)
        {
            MonoInternal.SendFile(_request, _response, filename, offset, length);
        }
        public override void SendResponseFromMemory(byte[] data, int length)
        {
            MonoInternal.SendContent(_request, _response, data, length);
        }
        public override void SendStatus(int statusCode, string statusDescription)
        {
            MonoInternal.SetStatus(_request, statusCode);
        }
        public override void SendUnknownResponseHeader(string name, string value)
        {
            MonoInternal.SetUnknownHeader(_request, name, value);
        }
        public override void SetEndOfSendNotification(EndOfSendNotification callback, object extraData)
        {
            _endSend = callback;
            _endSendData = extraData;
        }

        public void ProcessRequest()
            => HttpRuntime.ProcessRequest(this);

        public void Error(int status, string message)
            => MonoInternal.SetError(_request, _response, status, message);

        private unsafe void InitRequestHeader()
        {
            string header = MonoInternal.GetRequestHeader(_request);
            List<KeyValuePair<string, string>> list = new List<KeyValuePair<string, string>>(16);

            #region Parse Header
            fixed (char* p = header)
            {
                char* begin = p;
                char* end = begin + header.Length;

                int line = 0;
                char* start = begin;
                for (char* cur = begin; cur < end; ++cur)
                {
                    if (*cur == '\n')
                    {
                        if (line == 0)
                        {
                            #region Parse Method

                            _method = new string(start, 0, (int)(cur - start));

                            #endregion
                        }
                        else if (line == 1)
                        {
                            #region Parse Url

                            _rawUrl = new string(start, 0, (int)(cur - start));

                            char* t = start;
                            for (; t < cur; ++t)
                            {
                                if (*t == '?')
                                {
                                    _pathInfo = new string(start, 0, (int)(t - start));
                                    ++t;
                                    break;
                                }
                            }
                            if (cur > t)
                            {
                                _queryString = new string(t, 0, (int)(cur - t));
                            }
                            else
                            {
                                _pathInfo = _rawUrl;
                                _queryString = null;
                            }

                            #endregion
                        }
                        else if (line == 2)
                        {
                            #region Parse Version

                            _version = new string(start, 0, (int)(cur - start));

                            #endregion
                        }
                        else
                        {
                            #region Parse Headers

                            string tmp = null;

                            char* t = start;
                            for (; t < cur; ++t)
                            {
                                if (*t == ':')
                                {
                                    tmp = new string(start, 0, (int)(t - start));
                                    ++t;
                                    break;
                                }
                            }
                            if (tmp != null)
                            {
                                if (cur > t)
                                    list.Add(new KeyValuePair<string, string>(tmp, new string(t, 0, (int)(cur - t))));
                                else
                                    list.Add(new KeyValuePair<string, string>(tmp, string.Empty));
                            }

                            #endregion
                        }

                        ++line;

                        start = cur + 1;
                    }
                }
            }
            #endregion

            #region Format Headers

            _knownRequestHeaders = new string[RequestHeaderMaximum];
            string[][] headers = new string[list.Count][];
            int count = 0;
            int id;
            foreach (KeyValuePair<string, string> pair in list)
            {
                id = GetKnownRequestHeaderIndex(pair.Key);

                if (id >= 0)
                {
                    _knownRequestHeaders[id] = pair.Value;
                    continue;
                }

                headers[count++] = new string[] { pair.Key, pair.Value };
            }

            _unknownRequestHeaders = new string[count][];
            if (count > 0)
                Array.Copy(headers, 0, _unknownRequestHeaders, 0, count);

            #endregion
        }
        private static string HostNameFromString(string host)
        {
            if (string.IsNullOrEmpty(host))
                return null;

            int index = host.IndexOf(':');
            if (index == -1)
                return host;
            if (index == 0)
                return null;
            return host.Substring(0, index);
        }
        private static string AddressFromHostName(string host)
        {
            host = HostNameFromString(host);

            if (host == null || host.Length > 126)
                return null;

            IPAddress[] addresses;
            try
            {
                addresses = Dns.GetHostAddresses(host);
            }
            catch (SocketException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }

            if (addresses == null || addresses.Length == 0)
                return null;

            return addresses[0].ToString();
        }
        private static unsafe bool EqualsIgnoreCase(string a, string b)
        {
            int len = a.Length;
            if (len != b.Length)
                return false;

            char ac, bc;
            fixed (char* pa = a)
            {
                fixed (char* pb = b)
                {
                    for (int i = 0; i < len; ++i)
                    {
                        ac = *(pa + i);
                        bc = *(pb + i);
                        if (ac != bc && char.ToUpper(ac) != char.ToUpper(bc))
                            return false;
                    }
                }
            }
            return true;
        }
        private static string FormatFilePath(string path)
        {
            if (RunningOnWindows)
                return path.Replace('/', Path.DirectorySeparatorChar);
            return path;
        }

        public void Dispose()
        {
        }
    }
#endif
}
