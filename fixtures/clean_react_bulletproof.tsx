import React, { useMemo } from 'react';

export interface UserProfileProps {
    userId: string;
    isLoading: boolean;
    onUpdate: (id: string) => void;
}

export const UserProfile: React.FC<UserProfileProps> = ({ userId, isLoading, onUpdate }) => {
    const handleSave = () => {
        onUpdate(userId);
    };

    const contextValue = useMemo(() => ({ userId, isLoading }), [userId, isLoading]);

    if (isLoading) {
        return <div>Loading...</div>;
    }

    return (
        <div className="user-profile">
            <button onClick={handleSave}>Save User</button>
        </div>
    );
};
