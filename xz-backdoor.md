# FAQ on the xz-utils backdoor

## Background

On March 29th, 2024, a backdoor was discovered in
[xz-utils](https://xz.tukaani.org/xz-utils/), a suite of software that
gives developers lossless compression. This package is commonly used
for compressing release tarballs, software packages, kernel images,
and initramfs images. It is very widely distributed, statistically
your average Linux or macOS system will have it installed for
convenience.

This backdoor is very indirect and only shows up when a few _known_ specific
criteria are met. Others may be yet discovered! However, this backdoor is _at least_ 
triggerable by remote unprivileged systems connecting to public SSH ports. This has been
seen in the wild where it gets activated by connections - resulting in performance
issues, but we do not know yet what is required to bypass authentication (etc) with it.

We're reasonably sure the following things need to be true for your system
to be vulnerable:

* You need to be running a distro that uses glibc (for IFUNC)
* You need to have versions 5.6.0 or 5.6.1 of xz or liblzma installed
  (xz-utils provides the library liblzma) - likely only true if 
  running a rolling-release distro and updating religiously.

We know that the combination of *systemd* and *patched openssh* are
vulnerable but pending further analysis of the payload, we cannot
be certain that other configurations aren't.

While not scaremongering, it is important to be clear that **at this stage,
we got lucky, and there may well be other effects of the infected liblzma**.

If you're running a publicly accessible `sshd`, then you are - as a rule
of thumb for those not wanting to read the rest here - likely vulnerable.

If you aren't, it is unknown for now, but you should update as quickly as possible
because investigations are continuing.

TL:DR:
* Using a `.deb` or `.rpm` based distro with glibc and xz-5.6.0 or xz-5.6.1:
  * Using systemd on publicly accessible ssh: update RIGHT NOW NOW NOW
  * Otherwise: update RIGHT NOW NOW but prioritize the former
* Using another type of distribution:
  * With glibc and xz-5.6.0 or xz-5.6.1: update RIGHT NOW, but prioritize the above.

If all of these are the case, please update your systems to mitigate
this threat. For more information about affected systems and how to
update, please see [this
article](https://xeiaso.net/notes/2024/xz-vuln/) or check the
[xz-utils page on Repology](https://repology.org/project/xz/versions).

This is still a new situation. There is a lot we don't know. We don't
know if there are more possible exploit paths. We only know about this
one path. Please update your systems regardless. Unknown unknowns are
safer than known unknowns.

This is a living document. Everything in this document is made in good
faith of being accurate, but like I just said; we don't know much
about what's going on.

This is not a fault of sshd, systemd, or glibc, that is just how it
was made exploitable.

## Design

This backdoor has several components. At a high level:

* The release tarballs upstream publishes don't have the same code
  that GitHub has. This is common in C projects so that downstream
  consumers don't need to remember how to run autotools and autoconf.
  The version of `build-to-host.m4` in the release tarballs differs
  wildly from the upstream on GitHub.
* There are crafted test files in the `tests/` folder within the git repository too.
  These files are in the following commits:
    - `tests/files/bad-3-corrupt_lzma2.xz` ([cf44e4b7f5dfdbf8c78aef377c10f71e274f63c0](https://github.com/tukaani-project/xz/commit/cf44e4b7f5dfdbf8c78aef377c10f71e274f63c0), [74b138d2a6529f2c07729d7c77b1725a8e8b16f1](https://github.com/tukaani-project/xz/commit/74b138d2a6529f2c07729d7c77b1725a8e8b16f1))
    - `tests/files/good-large_compressed.lzma`
      ([cf44e4b7f5dfdbf8c78aef377c10f71e274f63c0](https://github.com/tukaani-project/xz/commit/cf44e4b7f5dfdbf8c78aef377c10f71e274f63c0),
      [74b138d2a6529f2c07729d7c77b1725a8e8b16f1](https://github.com/tukaani-project/xz/commit/74b138d2a6529f2c07729d7c77b1725a8e8b16f1))
* A script called by `build-to-host.m4` that unpacks this malicious
  test data and uses it to modify the build process.
* IFUNC, a mechanism in glibc that allows for indirect function calls,
  is used to perform runtime hooking/redirection of OpenSSH's
  authentication routines. IFUNC is a tool that is normally used for
  legitimate things, but in this case it is exploited for this attack
  path.
  
Normally upstream publishes release tarballs that are different than
the automatically generated ones in GitHub. In these modified
tarballs, a malicious version of `build-to-host.m4` is included to
execute a script during the build process.

This script (at least in versions 5.6.0 and 5.6.1) checks for various
conditions like the architecture of the machine. Here is a snippet of
the malicious script that gets unpacked by `build-to-host.m4` and an
explanation of what it does:

>```if ! (echo "$build" | grep -Eq "^x86_64" > /dev/null 2>&1) && (echo "$build" | grep -Eq "linux-gnu$" > /dev/null 2>&1);then```

* If amd64/x86_64 is the target of the build
* And if the target uses the name `linux-gnu` (mostly checks for the
  use of glibc)

It also checks for the toolchain being used:

> ```
>   if test "x$GCC" != 'xyes' > /dev/null 2>&1;then
>   exit 0
>   fi
>   if test "x$CC" != 'xgcc' > /dev/null 2>&1;then
>   exit 0
>   fi
>   LDv=$LD" -v"
>   if ! $LDv 2>&1 | grep -qs 'GNU ld' > /dev/null 2>&1;then
>   exit 0
> ```

And if you are trying to build a Debian or Red Hat package:

> ```if test -f "$srcdir/debian/rules" || test "x$RPM_ARCH" = "xx86_64";then```

This attack thusly seems to be targeted at amd64 systems running glibc
using either Debian or Red Hat derived distributions. Other systems
may be vulnerable at this time, but we don't know.

## Payload

If those conditions check, the payload is injected into the source
tree. We have not analyzed this payload in detail. Here are the main
things we know:

* The payload activates if the running program has the process
  name `/usr/sbin/sshd`. Systems that put `sshd` in
  `/usr/bin` or another folder may or may not be vulnerable.
* It may activate in other scenarios too, possibly even unrelated to ssh.
* We don't know what the payload is intended to do. We are
  investigating.
* Vanilla upstream OpenSSH isn't affected unless one of its
  dependencies links `liblzma`.
  <!-- Commented out because I can't actually see where this comes from yet. -->
  <!-- * _Update_: Lennart Poettering (via @Foxboron) [mentions](https://news.ycombinator.com/item?id=39867126) that it may happen
  via pam->libselinux->liblzma, and possibly in other cases too. -->
* The payload is loaded into `sshd` indirectly. `sshd` is often patched
  to support
  [systemd-notify](https://www.freedesktop.org/software/systemd/man/249/systemd-notify.html)
  so that other services can start when sshd is running. `liblzma` is
  loaded because it's depended on by other parts of `libsystemd`. This
  is not the fault of systemd, this is more unfortunate. The patch
  that most distributions use is available here:
  [openssh/openssh-portable#375](https://github.com/openssh/openssh-portable/pull/375).
* If this payload is loaded in openssh `sshd`, the
  `RSA_public_decrypt` function will be redirected into a malicious
  implementation. We have observed that this malicious implementation
  can be used to bypass authentication. Further research is being done
  to explain why.

## People

We do not want to speculate on the people behind this project in this
document. This is not a productive use of our time, and law
enforcement will be able to handle identifying those responsible. They
are likely patching their systems too.

xz-utils has two maintainers:

* Lasse Collin (_Larhzu_) who has maintained xz since the beginning
  (~2009), and before that, `lzma-utils`.
* Jia Tan (_JiaT75_) who started contributing to xz in the last 2-2.5
  years and gained commit access, and then release manager rights,
  about 1.5 years ago.

Lasse regularly has internet breaks and is on one at the moment,
started before this all kicked off. He has posted an update
at https://tukaani.org/xz-backdoor/ and is working with the community.

Please be patient with him as he gets up to speed and takes time
to analyse the situation carefully.

## Misc notes
* [Please __do not__ use `ldd` on untrusted binaries](https://jmmv.dev/2023/07/ldd-untrusted-binaries.html)
  * [[PATCH] ldd: Do not recommend binutils as the safer option](https://lore.kernel.org/linux-man/20231016061923.105814-1-siddhesh@gotplt.org/t/#u)

## Acknowledgements

* Andres Freund who discovered the issue and reported it to *linux-distros* and then *oss-security*.
* All the hard-working security teams helping to coordinate a response and push out fixes.
* Xe Iaso who resummarized this page for readability.

## References

* https://lwn.net/Articles/967180/
* https://www.openwall.com/lists/oss-security/2024/03/29/4
* https://boehs.org/node/everything-i-know-about-the-xz-backdoor
* https://tukaani.org/xz-backdoor/
* https://gynvael.coldwind.pl/?lang=en&id=782