use ExtUtils::MakeMaker;

WriteMakefile(
	NAME => "Crypt::Eksblowfish",
	VERSION_FROM => "lib/Crypt/Eksblowfish.pm",
	PREREQ_PM => {
		MIME::Base64 => "2.21",
		XSLoader => 0,
	},
);
