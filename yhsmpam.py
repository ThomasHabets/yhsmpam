#!/usr/bin/python
"""YHSMPAM 0.01

Copyright 2011 Google Inc.

YubiHSM for unix authentication.
"""

__author__ = 'Thomas Habets <habets@google.com>'

import pyhsm
import sys
import spwd
import subprocess
import getpass
import os
import re

DEFAULT_KEY_HANDLE = 2
DEFAULT_MIN_LENGTH = 20
DEFAULT_DEVICE='/dev/ttyACM0'

#
# Exception classes 
#


class Error(Exception):
    pass


class UseError(Error):
    pass

    
class CheckError(Error):
    pass


class CheckDatabaseError(CheckError):
    pass


class CheckMismatchError(CheckError):
    pass


class SetDatabaseError(Error):
    pass


#
# Password setter classes
#


class PasswordSetter(object):
    def ShouldWork(self):
        """PasswordSetter.ShouldWork(self) -> bool

        Preliminary check to see if running this implementation
        *should* work. Examples of checks is "does /usr/sbin/chpasswd
        exist?".

        Note that *only* the first password setter that returns True
        will be called. If it fails it will *not* continue to the next
        one. See class PasswordSetterDynamic.

        Return:  True if this implementation should work.
        """
        raise NotImplementedError()

    def Set(self, user, crypted):
        """Set(self, user, crypted) -> [str | None]

        Set encrypted password.

        Return: String to be printed to user. If empty string or None,
                nothing will be printed."""
        raise NotImplementedError()


class PasswordSetterInstructions(PasswordSetter):
    """PasswordSetterInstructions(PasswordSetter):

    This is a fallback implementation in case all others fail. It
    simply instructs the user to put the encrypted string in place
    manually.
    """
    def ShouldWork(self):
        return True

    def Set(self, user, crypted):
        return ("Please put this in user %s's password field:\n%s"
                % (user, crypted))


class PasswordSetterUsermod(PasswordSetter):
    """PasswordSetterChpasswd(PasswordSetter):

    usermod(8) is more portable than chpasswd, but it shows the
    encrypted password in a process listing.
    """
    def __init__(self, binary='/usr/sbin/usermod'):
        super(PasswordSetterUsermod, self).__init__()
        self.binary = binary

    def ShouldWork(self):
        return (os.access(self.binary, os.X_OK)
                and os.access('/etc/passwd', os.W_OK))

    def Set(self, user, crypted):
        try:
            proc = subprocess.Popen([self.binary, '-p', crypted])
            proc.wait()
            if proc.returncode:
                raise SetDatabaseError("usermod returned non-zero value %d"
                                       % proc.returncode)
        except IOError, e:
            raise SetDatabaseError(e)


class PasswordSetterChpasswd(PasswordSetter):
    """PasswordSetterChpasswd(PasswordSetter):

    chpasswd(8) seems to be standard on Linux and AIX, but not much
    else.
    """
    def __init__(self, binary='/usr/sbin/chpasswd'):
        super(PasswordSetterChpasswd, self).__init__()
        self.binary = binary

    def ShouldWork(self):
        return (os.access(self.binary, os.X_OK)
                and os.access('/etc/passwd', os.W_OK))

    def Set(self, user, crypted):
        try:
            proc = subprocess.Popen([self.binary, '-e'], stdin=subprocess.PIPE)
            proc.stdin.write('%s:%s\n' % (user, crypted))
            proc.stdin.close()
            proc.wait()
            if proc.returncode:
                raise SetDatabaseError("chpasswd returned non-zero value %d"
                                       % proc.returncode)
        except IOError, e:
            raise SetDatabaseError(e)


class PasswordSetterDynamic(PasswordSetter):
    def __init__(self, *methods):
        super(PasswordSetterDynamic, self).__init__()
        self.methods = methods
        if not self.methods:
            self.methods = [
                PasswordSetterChpasswd(),
                PasswordSetterUsermod(),
                PasswordSetterInstructions(),
                ]

    def Set(self, user, crypted):
        """Set(self, user, crypted) -> None

        Set password hash of user to already encrypted string.

        Args:
          user       Username.
          crypted    Encrypted password.   
        """
        for method in self.methods:
            if method.ShouldWork():
                return method.Set(user, crypted)
        else:
            raise SetDatabaseError("No")
        

#
# Main classes
#

class YHSMPAM(object):
    """class YHSMPAM(object):

    Backend class for setting and checking passwords against YubiHSM.

    Example use:
        hsm = YHSMPAM()
        hsm.CheckPassword('thomas', 'secret')
    """
    def __init__(self,
                 device=None,
                 key_handle=None,
                 min_length=None,
                 password_setter=PasswordSetterDynamic):
        """YHSMPAM.__init__(self, **kwargs)

        Args:
          device:           Device to use (e.g. /dev/ttyACM0)
          key_handle:       YubiHSM key index that encrypts the keys.
          min_length:       Pad passwords to this length.
          password_setter:  Callback class for setting the encrypted password.
        """
        super(YHSMPAM, self).__init__()
        self.password_setter = password_setter()

        self.device = device
        if self.device is None:
            self.device = DEFAULT_DEVICE

        self.key_handle = key_handle
        if self.key_handle is None:
            self.key_handle = DEFAULT_DEVICE

        self.min_length = min_length
        if self.min_length is None:
            self.min_length = DEFAULT_MIN_LENGTH

        try:
            self.hsm = pyhsm.YHSM(self.device)
        except Exception, e:
            raise Error('pyhsm: ' + str(e))

    def CheckPassword(self, user, password):
        """CheckPassword(self, user, password) -> None

        Check password with HSM.

        Get user AEAD block and nonce from /etc/shadow, check that
        it's formatted properly and send to HSM.
        """
        try:
            sp = spwd.getspnam(user)
        except KeyError:
            raise UseError("Insufficient permissions or user doesn't exist.")

        try:
            should_be_empty, alg, nonce, aead = sp.sp_pwd.split('$')
        except ValueError:
            raise CheckDatabaseError('Not standard format')

        if should_be_empty:
            raise CheckDatabaseError('Not standard format')

        if alg != 'YubiHSM':
            raise CheckDatabaseError('Not YubiHSM format')

        if not self.hsm.validate_aead(nonce.decode('hex'),
                                      self.key_handle,
                                      aead.decode('hex'),
                                      password.ljust(self.min_length,
                                                     chr(0x0))):
            raise CheckMismatchError("Wrong password according to HSM")

    def SetPassword(self, user, password):
        nonce = self.hsm.get_nonce().nonce
        aead = self.hsm.generate_aead_simple(nonce,
                                             self.key_handle,
                                             password.ljust(self.min_length,
                                                            chr(0x0)))
        pwstr = '$YubiHSM$%s$%s' % (nonce.encode('hex'),
                                    aead.data.encode('hex'))
            
        return self.password_setter.Set(user, pwstr)

    def SysInfo(self):
        return self.hsm.info()


class CommandProcessor(object):
    """YubiHSM PAM password command line tool.

    Meant to be run as the main program, but can also be used as a
    library.

    Command line use:
      CommandProcessor.Main(sys.argv)

    Library use:
      cmd = CommandProcessor()
      print cmd.RunCommand('help', ('set',))
      print cmd.RunCommand('set', ('thomas', 'secret'))
    """
    def __init__(self, configfile='/etc/yhsmpam/yhsmpam.conf'):
        super(CommandProcessor, self).__init__()
        self._argv0 = None
        self._commands = {}
        self._configfile = configfile
        self._key_handle = None
        self._device = None
        self._ReadConfig()
        self._hsm = None

        for cmd in [attr for attr in dir(self)
                    if attr.islower()
                    and attr.isalpha()]:
            self._commands[cmd] = self.__getattribute__(cmd)

    @classmethod
    def Main(cls, argv):
        cls.argv0 = argv[0]
        cmd = CommandProcessor()
        try:
            ret = cmd.RunCommand(argv[1], argv[2:])
            if ret:
                print ret
        except UseError, e:
            print e
            cmd.help('help')
            return 1
        except Error, e:
            print >>sys.stderr, "Exception:", type(e)
            if e.args:
                print >>sys.stderr, "Message:  ", e
            return 1

    def _ReadConfig(self):
        self._config = dict([tuple(re.split(r"\s+", line.strip(), 1))
                                   for line in open(self._configfile)])
        for key,val in self._config.iteritems():
            if key in ('key_handle'):
                self.__setattr__('_' + key, int(val))
            elif key in ('device'):
                self.__setattr__('_' + key, val)

    def RunCommand(self, cmd, args):
        return self._commands.get(cmd.lower(), self._UnknownCommand)(cmd,
                                                                     *args)

    def _InitHSM(self):
        if self._hsm is None:
            self._hsm = YHSMPAM(key_handle=self._key_handle,
                                device=self._device)

    def _UnknownCommand(self, cmd, *args):
        raise UseError("Unknown command: %s" % cmd)

    def _AboutCommand(self, cmd):
        try:
            return ' ' * 8 + self.__getattribute__(cmd.lower()).__doc__
        except AttributeError:
            return "Unknown command: %s" % cmd

    def _Usage(self):
        usagetext = '''Usage: %s [ <command> ] [ <options> ]

  If no command is given, the script will use PAM mode.

  PAM mode means that it will read two lines from stdin.  The first
  line is the username, the second is the password. If the password
  matches then "OK" is printed. Otherwise it will print "FAIL".

  Commands:
''' % CommandProcessor.argv0
        for cmdname, cmd in sorted(self._commands.items()):
            doc = cmd.__doc__
            usagetext += '    %s\n' % (doc.split('\n')[0])
        return usagetext

    #
    # Commands below this
    #

    def help(self, cmd, about=None, *args):
        """help                                 Show help text."""

        if about:
            return self._AboutCommand(about)

        return self._Usage()


    def set(self, cmd, username, password=None):
        """set <username> [<password>]          Set new password for user.

        Example sessions:
           $ sudo yhsmpam set thomas
           User password: <secret>
           $
        """
        self._InitHSM()
        if password is None:
            password = getpass.getpass('User password: ')
        return self._hsm.SetPassword(username, password)

    def check(self, cmd, username, password=None):
        """check <username> [<password>]        Check user password.

        Example sessions:
            $ sudo yhsmpam set marvin
            User password: <secret>
        """
        self._InitHSM()
        if password is None:
            password = getpass.getpass('User password: ')
        self._hsm.CheckPassword(username, password)
        return "Password correct"

    def sysinfo(self, cmd):
        """sysinfo                              Show YubiHSM system info.

        Example:
            $ sudo yhsmpam sysinfo
            YubiHSM 0.9.8 proto 1 ID 34ff6d063052383032560343
        """
        self._InitHSM()
        info = self._hsm.SysInfo()
        return ("YubiHSM %d.%d.%d proto %d ID %s"
                % (info.version_major,
                   info.version_minor,
                   info.version_build,
                   info.protocol_ver,
                   info.system_uid.encode('hex')))


def PAMHelper():
    user = raw_input("")
    password = raw_input("")
    try:
        hsm = YHSMPAM()
        hsm.CheckPassword(user, password)
        print "OK"
    except Error, e:
        print "FAIL"


def main():
    if len(sys.argv) == 1:
        return PAMHelper()
    else:
        CommandProcessor.Main(sys.argv)

if __name__ == '__main__':
    sys.exit(main())
