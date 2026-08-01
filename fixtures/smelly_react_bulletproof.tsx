import React, { useEffect, createContext } from 'react';

const AuthContext = createContext({ user: null });

export default function bad_component(props: any) {
    const click_handler = () => {
        console.log("clicked");
    };

    useEffect(() => {
        fetch('/api/user').then((res) => res.json());
    }, []);

    return (
        <AuthContext.Provider value={{ user: "admin" }}>
            <button onClick={click_handler}>Click</button>
        </AuthContext.Provider>
    );
}
