import setuptools

setuptools.setup(
    name="infra",
    version="0.0.1",

    description="An empty CDK Python app",
    author="author",

    package_dir={"": "infra"},
    packages=setuptools.find_packages(where="infra"),

    install_requires=[
        "aws-cdk.core==1.143.0",
    ],

    python_requires=">=3.6",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)
