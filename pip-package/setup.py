from setuptools import setup, find_packages

setup(
    name='openssh-session-keys',
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    packages=find_packages(),
    install_requires=[
        'python-ptrace', 'psutil',
    ],
    entry_points={
        'console_scripts': [
            'openssh-session-keys=openssh_session_keys.keys:main',            
        ],
    },
)
